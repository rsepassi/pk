#include "nik.h"

#include "log.h"
#include "sodium.h"
#include "taia.h"

#define NIK_IDENTIFIER "nik WireGuard v1"
#define NIK_KDF_CTX "wgikkdf1"
#define NIK_LABEL_MAC1 "mac1----"

#define MS_PER_SEC 1000

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64

// HMAC using blake2b
//
// HMAC: Keyed-Hashing for Message Authentication
// RFC 2104 https://datatracker.ietf.org/doc/html/rfc2104
//
// ipad = 0x36 repeated
// opad = 0x5C repeated
// H(K XOR opad, H(K XOR ipad, text))
//
// Based on libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c
static int hmac_blake2b(u8 *hmac, usize hmac_len, const u8 *key, usize key_len,
                        const u8 *input, usize input_len) {
  u8 khash[BLAKE2B_OUTBYTES];
  u8 pad[BLAKE2B_BLOCKBYTES];
  u8 ihash[BLAKE2B_OUTBYTES];
  crypto_generichash_blake2b_state istate;
  crypto_generichash_blake2b_state ostate;

  if (crypto_generichash_blake2b_init(&istate, 0, 0, sizeof(ihash)))
    return 1;
  if (crypto_generichash_blake2b_init(&ostate, 0, 0, hmac_len))
    return 1;

  if (key_len > sizeof(khash)) {
    if (crypto_generichash_blake2b(khash, sizeof(khash), key, key_len, 0, 0))
      return 1;
    key = khash;
    key_len = sizeof(khash);
  }

  memset(pad, 0x36, sizeof(pad));
  for (usize i = 0; i < key_len; ++i) {
    pad[i] ^= key[i];
  }
  if (crypto_generichash_blake2b_update(&istate, pad, sizeof(pad)))
    return 1;

  memset(pad, 0x5c, sizeof(pad));
  for (usize i = 0; i < key_len; ++i) {
    pad[i] ^= key[i];
  }
  if (crypto_generichash_blake2b_update(&ostate, pad, sizeof(pad)))
    return 1;

  sodium_memzero(pad, sizeof(pad));
  sodium_memzero(khash, sizeof(khash));

  if (crypto_generichash_blake2b_update(&istate, input, input_len))
    return 1;
  if (crypto_generichash_blake2b_final(&istate, ihash, sizeof(ihash)))
    return 1;

  if (crypto_generichash_blake2b_update(&ostate, ihash, sizeof(ihash)))
    return 1;
  if (crypto_generichash_blake2b_final(&ostate, hmac, hmac_len))
    return 1;

  return 0;
}

// Keeps a bitmask history of the last 64 messages
// Based on Appendix C in https://www.rfc-editor.org/rfc/rfc2401.txt
static bool counter_ok(CounterHistory *history, u64 counter, u64 max_seen) {
  if (counter == 0) {
    DLOG("counter=0");
    return false; // should never see counter=0
  }
  u64 window_size = sizeof(CounterHistory) * 8;

  // For a new max
  if (counter > max_seen) {
    u64 diff = counter - max_seen;
    if (diff < window_size) {
      *history <<= diff; // shift history
      *history |= 1;     // set bit for this packet
    } else {
      *history = 1; // this packet is much larger, so reset history
    }
    return true;
  }

  u64 diff = max_seen - counter;

  // older than the window size
  if (diff >= window_size) {
    DLOG("counter older than window_size");
    return false;
  }
  // already seen
  if (*history & (UINT64_C(1) << diff)) {
    DLOG("duplicate counter counter=%d max_seen=%d", (int)counter,
         (int)max_seen);
    return false;
  }

  // mark as seen
  *history |= (UINT64_C(1) << diff);
  return true;
}

static NIK_Status nik_dh_kdf2(const u8 *C, const CryptoKxPK *pk,
                              const CryptoKxSK *sk, const CryptoKxPK *bob,
                              u8 *T1, u8 *T2, bool initiator) {
  // T1, T2 := KDF_2(C, DH(sk, bob))

  // DH(E_priv_i, S_pub_r)
  CryptoKxTx dh;
  if (initiator) {
    if (crypto_kx_client_session_keys((u8 *)&dh, 0, (u8 *)pk, (u8 *)sk,
                                      (u8 *)bob))
      return 1;
  } else {
    if (crypto_kx_server_session_keys((u8 *)&dh, 0, (u8 *)pk, (u8 *)sk,
                                      (u8 *)bob))
      return 1;
  }

  // T0 = HMAC(C, dh)
  STATIC_CHECK(crypto_kdf_KEYBYTES == 32);
  u8 T0[crypto_kdf_KEYBYTES];
  if (hmac_blake2b(T0, sizeof(T0), C, NIK_CHAIN_SZ, (u8 *)&dh, sizeof(dh)))
    return 1;
  // T1 = HMAC(T0, 1)
  if (crypto_kdf_derive_from_key(T1, 32, 1, NIK_KDF_CTX, T0))
    return 1;

  if (T2) {
    // T2 = HMAC(T0 T1, 2)
    if (crypto_kdf_derive_from_key(T2, 32, 2, NIK_KDF_CTX, T1))
      return 1;
  }

  return 0;
}

NIK_Status nik_handshake_respond(NIK_Handshake *state, u32 id,
                                 const NIK_HandshakeMsg1 *msg1,
                                 NIK_HandshakeMsg2 *msg2) {
  // Second message: Responder to Initiator
  sodium_memzero(msg2, sizeof(NIK_HandshakeMsg2));
  // Set message type
  msg2->type = NIK_Msg_R2I;
  msg2->sender = id;
  state->sender = msg2->sender;
  // Copy receiver
  msg2->receiver = msg1->sender;

  u8 *C_r = state->chaining_key;
  crypto_generichash_blake2b_state *H_state = &state->hash;

  // (E_priv_r, E_pub_r) := DH-Generate()
  // msg.ephemeral := E_pub_r
  CryptoKxSK *E_priv_r = &state->ephemeral_sk;
  CryptoKxPK *E_pub_r = &state->ephemeral_pk;
  if (crypto_kx_keypair((u8 *)E_pub_r, (u8 *)E_priv_r))
    return 1;
  memcpy(&msg2->ephemeral, E_pub_r, sizeof(*E_pub_r));

  // C_r := KDF_1(C_r, E_pub_r)
  {
    // T0 = HMAC(C_r, E_pub_r)
    STATIC_CHECK(crypto_kdf_KEYBYTES == 32);
    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_r, NIK_CHAIN_SZ, (u8 *)E_pub_r,
                     sizeof(*E_pub_r)))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_r := Hash(H_r || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg2->ephemeral,
                                        sizeof(msg2->ephemeral)))
    return 1;

  // C_r := KDF1(C_r, DH(E_priv_r, E_pub_i))
  if (nik_dh_kdf2(C_r, E_pub_r, E_priv_r, &msg1->ephemeral, C_r, 0, false))
    return 1;
  // C_r := KDF1(C_r, DH(E_priv_r, S_pub_i))
  if (nik_dh_kdf2(C_r, E_pub_r, E_priv_r, state->keys.bob, C_r, 0, false))
    return 1;

  // (C_r, T, K) := KDF3(C_r, Q);
  u8 T[32] = {0};
  u8 K[32] = {0};
  {
    STATIC_CHECK(crypto_secretbox_KEYBYTES == 32);
    u8 Q0[crypto_secretbox_KEYBYTES] = {0};
    u8 *Q = Q0;
    if (state->keys.psk)
      Q = (u8 *)state->keys.psk;

    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_r, NIK_CHAIN_SZ, Q,
                     crypto_secretbox_KEYBYTES))
      return 1;

    if (crypto_kdf_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX, C_r))
      return 1;
    if (crypto_kdf_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T))
      return 1;
  }

  // H_r := Hash(H_r || T)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)T, sizeof(T)))
    return 1;

  // msg.empty := AEAD(K, 0, e, H_r)
  {
    // Snapshot H_r
    u8 H[32];
    crypto_generichash_blake2b_state H_r;
    memcpy(&H_r, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_r, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, e, H_r)
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    // u8 *empty = 0;
    u8 dummy_ptr[1];
    u8 *empty = dummy_ptr;
    u8 *mempty = (u8 *)&msg2->empty;
    STATIC_CHECK(sizeof(msg2->empty) == crypto_box_MACBYTES);
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            empty, mempty, 0, 0, 0, H, sizeof(H), 0, zero_nonce, K))
      return 1;
  }

  // H_r := Hash(H_r || msg.empty)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg2->empty,
                                        sizeof(msg2->empty)))
    return 1;

  return 0;
}

NIK_Status nik_handshake_init(NIK_Handshake *state, const NIK_Keys keys, u32 id,
                              NIK_HandshakeMsg1 *msg) {
  // First message: Initiator to Responder
  sodium_memzero(msg, sizeof(NIK_HandshakeMsg1));
  // Set message type
  msg->type = NIK_Msg_I2R;
  msg->sender = id;
  state->sender = msg->sender;

  // Initiator static key
  CryptoKxPK *S_pub_i = keys.pk;
  CryptoKxSK *S_priv_i = keys.sk;

  // Responder static key
  CryptoKxPK *S_pub_r = keys.bob;

  // C_i := Hash(Construction)
  u8 *C_i = state->chaining_key;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8 *)NIK_CONSTRUCTION,
                                 sizeof(NIK_CONSTRUCTION) - 1, 0, 0))
    return 1;
  // H_i
  crypto_generichash_blake2b_state *H_state = &state->hash;
  if (crypto_generichash_blake2b_init(H_state, 0, 0, 32))
    return 1;
  // C_i := Hash(Construction)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)NIK_CONSTRUCTION,
                                        sizeof(NIK_CONSTRUCTION) - 1))
    return 1;
  // H_i := Hash(C_i || Identifier)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)NIK_IDENTIFIER,
                                        sizeof(NIK_IDENTIFIER) - 1))
    return 1;
  // H_i := Hash(H_i || S_pub_r)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)S_pub_r,
                                        sizeof(*S_pub_r)))
    return 1;

  // (E_priv_i, E_pub_i) := DH-Generate()
  // msg.ephemeral := E_pub_i
  CryptoKxSK *E_priv_i = &state->ephemeral_sk;
  CryptoKxPK *E_pub_i = &state->ephemeral_pk;
  if (crypto_kx_keypair((u8 *)E_pub_i, (u8 *)E_priv_i))
    return 1;
  memcpy(&msg->ephemeral, E_pub_i, sizeof(*E_pub_i));

  // C_i := KDF_1(C_i, E_pub_i)
  {

    // temp = HMAC-Blake2s(initiator.chaining_key, msg.unencrypted_ephemeral,
    // 32) initiator.chaining_key = HMAC(temp, 0x1)

    // T0 = HMAC(C_i, E_pub_i)
    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ, (u8 *)E_pub_i,
                     sizeof(*E_pub_i)))
      return 1;
    // C_i = T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_i := Hash(H_i || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->ephemeral,
                                        sizeof(msg->ephemeral)))
    return 1;

  // C_i, k := KDF_2(C_i, DH(E_priv_i, S_pub_r))
  u8 K[32];
  if (nik_dh_kdf2(C_i, E_pub_i, E_priv_i, S_pub_r, C_i, K, true))
    return 1;

  // msg.static := AEAD(K, 0, S_pub_i, H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, S_pub_i, H_i)
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(msg->statik) == crypto_box_MACBYTES + sizeof(*S_pub_i));
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            (u8 *)&msg->statik.key, (u8 *)&msg->statik.tag, 0, (u8 *)S_pub_i,
            sizeof(*S_pub_i), H, sizeof(H), 0, zero_nonce, K))
      return 1;
  }

  // H_i := Hash(H_i || msg.static)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->statik,
                                        sizeof(msg->statik)))
    return 1;

  // C_i, K := KDF_2(C_i, DH(S_priv_i, S_pub_r))
  if (nik_dh_kdf2(C_i, S_pub_i, S_priv_i, S_pub_r, C_i, K, true))
    return 1;

  // msg.timestamp := AEAD(K, 0, Timestamp(), H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // Timestamp()
    u8 timestamp[sizeof(msg->timestamp.timestamp)];
    {
      struct taia ts;
      taia_now(&ts);
      tain_pack((char *)timestamp, &ts);
    }

    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(msg->timestamp) ==
                 crypto_box_MACBYTES + sizeof(timestamp));
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            msg->timestamp.timestamp, (u8 *)&msg->timestamp.tag, 0, timestamp,
            sizeof(timestamp), H, sizeof(H), 0, zero_nonce, K))
      return 1;
  }

  // H_i := Hash(H_i || msg.timestamp)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->timestamp,
                                        sizeof(msg->timestamp)))
    return 1;

  // mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public),
  //            msg[0:offsetof(msg.mac1)])
  {
    u8 m_hash[32];
    crypto_generichash_blake2b_state m_state;
    if (crypto_generichash_blake2b_init(&m_state, 0, 0, sizeof(m_hash)))
      return 1;
    if (crypto_generichash_blake2b_update(&m_state, (u8 *)NIK_LABEL_MAC1,
                                          sizeof(NIK_LABEL_MAC1)))
      return 1;
    if (crypto_generichash_blake2b_update(&m_state, (u8 *)S_pub_r,
                                          sizeof(*S_pub_r)))
      return 1;
    if (crypto_generichash_blake2b_final(&m_state, m_hash, sizeof(m_hash)))
      return 1;

    if (crypto_generichash_blake2b((u8 *)&msg->mac1, sizeof(msg->mac1),
                                   (u8 *)msg, ((u8 *)&msg->mac1 - (u8 *)msg),
                                   m_hash, sizeof(m_hash)))
      return 1;
  }

  state->initiator = true;
  state->keys = keys;

  return 0;
}

NIK_Status nik_handshake_respond_check(NIK_Handshake *state,
                                       const NIK_HandshakeMsg2 *msg) {
  // Initiator checks the Responder message and constructs identical state
  if (msg->type != NIK_Msg_R2I)
    return 1;

  // Check sender id
  if (state->sender != msg->receiver)
    return 1;
  state->receiver = msg->sender;

  u8 *C_i = state->chaining_key;
  crypto_generichash_blake2b_state *H_state = &state->hash;

  // C_i := KDF_1(C_i, E_pub_r)
  {
    // T0 = HMAC(C_i, E_pub_r)
    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ, (u8 *)&msg->ephemeral,
                     sizeof(msg->ephemeral)))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_r := Hash(H_r || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->ephemeral,
                                        sizeof(msg->ephemeral)))
    return 1;

  // C_i := KDF1(C_i, DH(E_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, &state->ephemeral_pk, &state->ephemeral_sk,
                  &msg->ephemeral, C_i, 0, true))
    return 1;
  // C_i := KDF1(C_i, DH(S_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, state->keys.pk, state->keys.sk, &msg->ephemeral, C_i, 0,
                  true))
    return 1;

  // (C_i, T, K) := KDF3(C_i, Q);
  u8 T[32] = {0};
  u8 K[32] = {0};
  {
    STATIC_CHECK(crypto_secretbox_KEYBYTES == 32);
    u8 Q0[crypto_secretbox_KEYBYTES] = {0};
    u8 *Q = Q0;
    if (state->keys.psk)
      Q = (u8 *)state->keys.psk;

    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ, Q,
                     crypto_secretbox_KEYBYTES))
      return 1;

    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX, C_i))
      return 1;
    if (crypto_kdf_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T))
      return 1;
  }

  // H_i := Hash(H_i || T)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)T, sizeof(T)))
    return 1;

  // msg.empty := AEAD(K, 0, e, H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, e, H_i)
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    u8 dummy_ptr[1];
    u8 *empty = dummy_ptr;
    u8 *mempty = (u8 *)&msg->empty;
    if (crypto_aead_chacha20poly1305_decrypt_detached(0, 0, empty, 0, mempty, H,
                                                      sizeof(H), zero_nonce, K))
      return 1;
  }

  // H_i := Hash(H_i || msg.empty)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->empty,
                                        sizeof(msg->empty)))
    return 1;

  return 0;
}

NIK_Status nik_handshake_init_check(NIK_Handshake *state, const NIK_Keys keys,
                                    const NIK_HandshakeMsg1 *msg) {
  // Responder checks the first message and constructs identical state
  if (msg->type != NIK_Msg_I2R)
    return 1;

  state->receiver = msg->sender;

  // Responder static key
  CryptoKxPK *S_pub_r = keys.pk;
  CryptoKxSK *S_priv_r = keys.sk;

  // Validate mac1 up front
  // mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public),
  //            msg[0:offsetof(msg.mac1)])
  {
    u8 m_hash[32];
    crypto_generichash_blake2b_state m_state;
    if (crypto_generichash_blake2b_init(&m_state, 0, 0, sizeof(m_hash)))
      return 1;
    if (crypto_generichash_blake2b_update(&m_state, (u8 *)NIK_LABEL_MAC1,
                                          sizeof(NIK_LABEL_MAC1)))
      return 1;
    if (crypto_generichash_blake2b_update(&m_state, (u8 *)S_pub_r,
                                          sizeof(*S_pub_r)))
      return 1;
    if (crypto_generichash_blake2b_final(&m_state, m_hash, sizeof(m_hash)))
      return 1;

    u8 mac1[sizeof(msg->mac1)];
    if (crypto_generichash_blake2b(mac1, sizeof(mac1), (u8 *)msg,
                                   ((u8 *)&msg->mac1 - (u8 *)msg), m_hash,
                                   sizeof(m_hash)))
      return 1;

    if (sodium_memcmp(mac1, (u8 *)&msg->mac1, sizeof(mac1)))
      return 1;
  }

  // Initiator static key
  CryptoKxPK *S_pub_i = keys.bob;

  // C_i := Hash(Construction)
  u8 *C_i = state->chaining_key;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8 *)NIK_CONSTRUCTION,
                                 sizeof(NIK_CONSTRUCTION) - 1, 0, 0))
    return 1;
  // H_i
  crypto_generichash_blake2b_state *H_state = &state->hash;
  if (crypto_generichash_blake2b_init(H_state, 0, 0, 32))
    return 1;
  // C_i := Hash(Construction)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)NIK_CONSTRUCTION,
                                        sizeof(NIK_CONSTRUCTION) - 1))
    return 1;
  // H_i := Hash(C_i || Identifier)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)NIK_IDENTIFIER,
                                        sizeof(NIK_IDENTIFIER) - 1))
    return 1;
  // H_i := Hash(H_i || S_pub_r)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)S_pub_r,
                                        sizeof(*S_pub_r)))
    return 1;

  // C_i := KDF_1(C_i, E_pub_i)
  {
    // T0 = HMAC(C_i, E_pub_i)
    STATIC_CHECK(crypto_kdf_KEYBYTES == 32);
    u8 T0[crypto_kdf_KEYBYTES];
    if (hmac_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ, (u8 *)&msg->ephemeral,
                     sizeof(msg->ephemeral)))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_i := Hash(H_i || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->ephemeral,
                                        sizeof(msg->ephemeral)))
    return 1;

  // C_i, k := KDF_2(C_i, DH(S_priv_r, E_pub_i))
  u8 K[32];
  if (nik_dh_kdf2(C_i, S_pub_r, S_priv_r, &msg->ephemeral, C_i, K, false))
    return 1;

  // msg.static := AEAD(K, 0, S_pub_i, H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, S_pub_i, H_i)
    u8 H_decrypt[sizeof(*S_pub_i)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    if (crypto_aead_chacha20poly1305_decrypt_detached(
            H_decrypt, 0, (u8 *)&msg->statik.key, sizeof(msg->statik.key),
            (u8 *)&msg->statik.tag, H, sizeof(H), zero_nonce, K))
      return 1;

    if (sodium_memcmp(H_decrypt, S_pub_i, sizeof(*S_pub_i)))
      return 1;
  }

  // H_i := Hash(H_i || msg.static)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->statik,
                                        sizeof(msg->statik)))
    return 1;

  // C_i, K := KDF_2(C_i, DH(S_priv_r, S_pub_i))
  if (nik_dh_kdf2(C_i, S_pub_r, S_priv_r, S_pub_i, C_i, K, false))
    return 1;

  // msg.timestamp := AEAD(K, 0, Timestamp(), H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    u8 T_decrypt[sizeof(msg->timestamp.timestamp)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    if (crypto_aead_chacha20poly1305_decrypt_detached(
            T_decrypt, 0, (u8 *)&msg->timestamp.timestamp,
            sizeof(msg->timestamp.timestamp), (u8 *)&msg->timestamp.tag, H,
            sizeof(H), zero_nonce, K))
      return 1;
  }

  // H_i := Hash(H_i || msg.timestamp)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->timestamp,
                                        sizeof(msg->timestamp)))
    return 1;

  state->keys = keys;
  state->initiator = false;

  return 0;
}

NIK_Status nik_handshake_final(NIK_Handshake *state, NIK_Session *session) {
  u8 *C = state->chaining_key;

  *session = (NIK_Session){0};
  session->sender = state->sender;
  session->receiver = state->receiver;
  session->isinitiator = state->initiator;

  CryptoKxTx *send = &session->send;
  CryptoKxTx *recv = &session->recv;
  if (!state->initiator) {
    send = &session->recv;
    recv = &session->send;
  }

  // (T_send, T_recv) := KDF2(C, e)
  {
    // T0 = HMAC(C, e)
    u8 T0[crypto_kdf_KEYBYTES];
    u8 e[32] = {0};
    if (hmac_blake2b(T0, sizeof(T0), C, NIK_CHAIN_SZ, e, sizeof(e)))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key((u8 *)send, sizeof(session->send), 1,
                                   NIK_KDF_CTX, T0))
      return 1;
    // T2 = HMAC(T1, 2)
    if (crypto_kdf_derive_from_key((u8 *)recv, sizeof(session->recv), 2,
                                   NIK_KDF_CTX, (u8 *)send))
      return 1;
  }

  sodium_memzero(state, sizeof(NIK_Handshake));

  return 0;
}

u64 nik_sendmsg_sz(u64 len) { return sizeof(NIK_MsgHeader) + len + len % 16; }

NIK_Status nik_msg_send(NIK_Session *session, Str payload, Str send) {
  if (nik_sendmsg_sz(payload.len) != send.len) {
    DLOG("send bad size");
    return 1;
  }

  if (payload.len > UINT16_MAX)
    return 1;

  sodium_memzero(send.buf, send.len);

  NIK_MsgHeader *header = (NIK_MsgHeader *)send.buf;
  u8 *crypt = (u8 *)(send.buf + sizeof(NIK_MsgHeader));
  u64 payload_len = send.len - sizeof(NIK_MsgHeader);
  memcpy(crypt, payload.buf, payload.len);
  header->payload_len = payload.len;

  header->type = NIK_Msg_Data;
  header->receiver = session->receiver;
  header->counter = ++session->send_n;

  u8 nonce[crypto_box_NONCEBYTES] = {0};
  *(u64 *)nonce = header->counter;
  if (crypto_aead_chacha20poly1305_encrypt_detached(
          crypt, (u8 *)&header->tag, 0, crypt, payload_len,
          (u8 *)&header->payload_len, sizeof(header->payload_len), 0, nonce,
          (u8 *)&session->send)) {
    DLOG("send bad encrypt");
    return 1;
  }

  return 0;
}

NIK_Status nik_msg_recv(NIK_Session *session, Str *msg) {
  if (msg->len < sizeof(NIK_MsgHeader)) {
    DLOG("recv bad length");
    return 1;
  }

  NIK_MsgHeader *header = (NIK_MsgHeader *)msg->buf;
  u8 *crypt = (u8 *)(msg->buf + sizeof(NIK_MsgHeader));
  u64 crypt_len = msg->len - sizeof(NIK_MsgHeader);

  if (!(header->type == NIK_Msg_Data || header->type == NIK_Msg_Keepalive)) {
    DLOG("recv bad type");
    return 1;
  }
  if (header->receiver != session->sender) {
    DLOG("recv bad receiver");
    return 1;
  }

  u64 counter = header->counter;
  u64 payload_len = header->payload_len;

  // Inplace decrypt: msg (and header) will be rewritten
  u8 nonce[crypto_box_NONCEBYTES] = {0};
  *(u64 *)nonce = header->counter;
  if (crypto_aead_chacha20poly1305_decrypt_detached(
          msg->buf, 0, crypt, crypt_len, (u8 *)&header->tag,
          (u8 *)&header->payload_len, sizeof(header->payload_len), nonce,
          (u8 *)&session->recv)) {
    DLOG("recv bad decrypt");
    return 1;
  }

  if (!counter_ok(&session->counter_history, counter, session->counter_max)) {
    DLOG("recv bad counter");
    return 1;
  }
  if (counter > session->counter_max)
    session->counter_max = counter;

  ++session->recv_n;

  msg->len = payload_len;
  return 0;
}
