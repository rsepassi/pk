#include "nik.h"

#include "log.h"
#include "sodium.h"
#include "taia.h"

#define NIK_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b"
#define NIK_IDENTIFIER "xos WireGuard v1"
#define NIK_KDF_CTX "wgikkdf1"

static int nik_dh_kdf2(const u8 *C, const CryptoKxPK *pk, const CryptoKxSK *sk,
                       const CryptoKxPK *bob, u8 *T1, u8 *T2, bool initiator) {
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
  if (crypto_generichash_blake2b(T0, sizeof(T0), (u8 *)&dh, sizeof(dh), C, 32))
    return 1;
  // T1 = HMAC(T0, 1)
  if (crypto_kdf_derive_from_key(T1, 32, 1, NIK_KDF_CTX, T0))
    return 1;

  if (T2) {
    // T2 = HMAC(T0 T1, 2)
    if (crypto_kdf_derive_from_key(T2, 32, 2, NIK_KDF_CTX, T0))
      return 1;
  }

  return 0;
}

int nik_handshake_respond(const NIK_ResponderHandshakeRequest *req,
                          NIK_HandshakeState *state, NIK_HandshakeMsg2 *msg) {
  // Second message: Responder to Initiator
  memset(msg, 0, sizeof(NIK_HandshakeMsg2));
  // Set message type
  msg->type = NIK_Msg_R2I;
  // Assign random sender id
  randombytes_buf((u8 *)&msg->sender, sizeof(msg->sender));
  // Copy receiver
  msg->receiver = req->msg->sender;

  u8 *C_r = state->C;
  crypto_generichash_blake2b_state *H_state = &state->H;

  // (E_priv_r, E_pub_r) := DH-Generate()
  // msg.ephemeral := E_pub_r
  CryptoKxSK *E_priv_r = &state->E;
  CryptoKxPK *E_pub_r = &msg->ephemeral;
  if (crypto_kx_keypair((u8 *)E_pub_r, (u8 *)E_priv_r))
    return 1;

  // C_r := KDF_1(C_r, E_pub_r)
  {
    // T0 = HMAC(C_r, E_pub_r)
    STATIC_CHECK(crypto_kdf_KEYBYTES == 32);
    u8 T0[crypto_kdf_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), (u8 *)E_pub_r,
                                   sizeof(*E_pub_r), C_r, NIK_CHAIN_SZ))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_r := Hash(H_r || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->ephemeral,
                                        sizeof(msg->ephemeral)))
    return 1;

  // C_r := KDF1(C_r, DH(E_priv_r, E_pub_i))
  if (nik_dh_kdf2(C_r, E_pub_r, E_priv_r, &req->msg->ephemeral, C_r, 0, false))
    return 1;
  // C_r := KDF1(C_r, DH(E_priv_r, S_pub_i))
  if (nik_dh_kdf2(C_r, E_pub_r, E_priv_r, req->keys.bob, C_r, 0, false))
    return 1;

  // (C_r, T, K) := KDF3(C_r, Q);
  u8 T[32] = {0};
  u8 K[32] = {0};
  {
    u8 Q[32] = {0};

    u8 T0[crypto_kdf_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), Q, sizeof(Q), C_r,
                                   NIK_CHAIN_SZ))
      return 1;

    if (crypto_kdf_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T0))
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
    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(msg->empty) == crypto_box_MACBYTES);
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&msg->empty, 0, H, sizeof(H), 0, 0, 0, zero_nonce,
            K))
      return 1;
  }

  // H_r := Hash(H_r || msg.empty)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->empty,
                                        sizeof(msg->empty)))
    return 1;

  return 0;
}

int nik_handshake_init(const NIK_InitiatorHandshakeRequest *req,
                       NIK_HandshakeState *state, NIK_HandshakeMsg1 *msg) {
  // First message: Initiator to Responder
  memset(msg, 0, sizeof(NIK_HandshakeMsg1));
  // Set message type
  msg->type = NIK_Msg_I2R;
  // Assign random sender id
  randombytes_buf((u8 *)&msg->sender, sizeof(msg->sender));

  // Initiator static key
  CryptoKxPK *S_pub_i = req->keys.keys->pk;
  CryptoKxSK *S_priv_i = req->keys.keys->sk;

  // Responder static key
  CryptoKxPK *S_pub_r = req->keys.bob;

  // C_i := Hash(Construction)
  u8 *C_i = state->C;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8 *)NIK_CONSTRUCTION,
                                 sizeof(NIK_CONSTRUCTION) - 1, 0, 0))
    return 1;
  // H_i
  crypto_generichash_blake2b_state *H_state = &state->H;
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
  CryptoKxSK *E_priv_i = &state->E;
  CryptoKxPK *E_pub_i = &msg->ephemeral;
  if (crypto_kx_keypair((u8 *)E_pub_i, (u8 *)E_priv_i))
    return 1;

  // C_i := KDF_1(C_i, E_pub_i)
  {
    // T0 = HMAC(C_i, E_pub_i)
    STATIC_CHECK(crypto_kdf_KEYBYTES == 32);
    u8 T0[crypto_kdf_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), (u8 *)E_pub_i,
                                   sizeof(*E_pub_i), C_i, NIK_CHAIN_SZ))
      return 1;
    // T1 = HMAC(T0, 1)
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

  // msg.static := AEAD(K, 0, Hash(S_pub_i), H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // Hash(S_pub_i)
    u8 H_S_pub_i[sizeof(*S_pub_i)];
    if (crypto_generichash_blake2b(H_S_pub_i, sizeof(H_S_pub_i), (u8 *)S_pub_i,
                                   sizeof(*S_pub_i), 0, 0))
      return 1;

    // AEAD(K, 0, Hash(S_pub_i), H_i)
    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(msg->statik) ==
                 crypto_box_MACBYTES + sizeof(H_S_pub_i));
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&msg->statik.tag, 0, H, sizeof(H), H_S_pub_i,
            sizeof(H_S_pub_i), 0, zero_nonce, K))
      return 1;
    // plaintext = Hash(S_pub_i)
    memcpy((u8 *)&msg->statik.key, (u8 *)&H_S_pub_i, sizeof(H_S_pub_i));
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

    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(msg->timestamp) ==
                 crypto_box_MACBYTES + sizeof(timestamp));
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&msg->timestamp.tag, 0, H, sizeof(H), timestamp,
            sizeof(timestamp), 0, zero_nonce, K))
      return 1;
    memcpy(msg->timestamp.timestamp, timestamp, sizeof(timestamp));
  }

  // H_i := Hash(H_i || msg.timestamp)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&msg->timestamp,
                                        sizeof(msg->timestamp)))
    return 1;

  return 0;
}

int nik_handshake_respond_check(const NIK_InitiatorHandshakeRequest *req,
                                NIK_HandshakeState *state) {
  // Initiator checks the Responder message and constructs identical state
  if (req->msg2->type != NIK_Msg_R2I)
    return 1;

  // Check sender id
  if (req->msg1->sender != req->msg2->receiver)
    return 1;

  u8 *C_i = state->C;
  crypto_generichash_blake2b_state *H_state = &state->H;

  // C_i := KDF_1(C_i, E_pub_r)
  {
    // T0 = HMAC(C_i, E_pub_r)
    u8 T0[crypto_kdf_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), (u8 *)&req->msg2->ephemeral,
                                   sizeof(req->msg2->ephemeral), C_i,
                                   NIK_CHAIN_SZ))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_r := Hash(H_r || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&req->msg2->ephemeral,
                                        sizeof(req->msg2->ephemeral)))
    return 1;

  // C_i := KDF1(C_i, DH(E_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, &req->msg1->ephemeral, &state->E, &req->msg2->ephemeral,
                  C_i, 0, true))
    return 1;
  // C_i := KDF1(C_i, DH(S_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, req->keys.keys->pk, req->keys.keys->sk,
                  &req->msg2->ephemeral, C_i, 0, true))
    return 1;

  // (C_i, T, K) := KDF3(C_i, Q);
  u8 T[32] = {0};
  u8 K[32] = {0};
  {
    u8 Q[32] = {0};

    u8 T0[crypto_kdf_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), Q, sizeof(Q), C_i,
                                   NIK_CHAIN_SZ))
      return 1;

    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX, T0))
      return 1;
    if (crypto_kdf_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T0))
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
    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    CryptoAuthTag tag;
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&tag, 0, H, sizeof(H), 0, 0, 0, zero_nonce, K))
      return 1;
    if (sodium_memcmp((u8 *)&tag, (u8 *)&req->msg2->empty, sizeof(tag)))
      return 1;
  }

  // H_i := Hash(H_i || msg.empty)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&req->msg2->empty,
                                        sizeof(req->msg2->empty)))
    return 1;

  return 0;
}

int nik_handshake_init_check(const NIK_ResponderHandshakeRequest *req,
                             NIK_HandshakeState *state) {
  // Responder checks the first message and constructs identical state
  if (req->msg->type != NIK_Msg_I2R)
    return 1;

  // Responder static key
  CryptoKxPK *S_pub_r = req->keys.keys->pk;
  CryptoKxSK *S_priv_r = req->keys.keys->sk;

  // Initiator static key
  CryptoKxPK *S_pub_i = req->keys.bob;

  // C_i := Hash(Construction)
  u8 *C_i = state->C;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8 *)NIK_CONSTRUCTION,
                                 sizeof(NIK_CONSTRUCTION) - 1, 0, 0))
    return 1;
  // H_i
  crypto_generichash_blake2b_state *H_state = &state->H;
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
    if (crypto_generichash_blake2b(T0, sizeof(T0), (u8 *)&req->msg->ephemeral,
                                   sizeof(req->msg->ephemeral), C_i,
                                   NIK_CHAIN_SZ))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX, T0))
      return 1;
  }

  // H_i := Hash(H_i || msg.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&req->msg->ephemeral,
                                        sizeof(req->msg->ephemeral)))
    return 1;

  // C_i, k := KDF_2(C_i, DH(S_priv_r, E_pub_i))
  u8 K[32];
  if (nik_dh_kdf2(C_i, S_pub_r, S_priv_r, &req->msg->ephemeral, C_i, K, false))
    return 1;

  // msg.static := AEAD(K, 0, Hash(S_pub_i), H_i)
  {
    // Snapshot H_i
    u8 H[32];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // Hash(S_pub_i)
    u8 H_S_pub_i[sizeof(*S_pub_i)];
    if (crypto_generichash_blake2b(H_S_pub_i, sizeof(H_S_pub_i), (u8 *)S_pub_i,
                                   sizeof(*S_pub_i), 0, 0))
      return 1;

    // AEAD(K, 0, Hash(S_pub_i), H_i)
    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    CryptoAuthTag tag;
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&tag, 0, H, sizeof(H), H_S_pub_i, sizeof(H_S_pub_i),
            0, zero_nonce, K))
      return 1;

    if (sodium_memcmp((u8 *)&tag, (u8 *)&req->msg->statik.tag, sizeof(tag)))
      return 1;
  }

  // H_i := Hash(H_i || msg.static)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&req->msg->statik,
                                        sizeof(req->msg->statik)))
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

    u8 H_crypt[sizeof(H)];
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    CryptoAuthTag tag;
    if (crypto_aead_chacha20poly1305_encrypt_detached(
            H_crypt, (u8 *)&tag, 0, H, sizeof(H),
            (u8 *)&req->msg->timestamp.timestamp,
            sizeof(req->msg->timestamp.timestamp), 0, zero_nonce, K))
      return 1;

    if (sodium_memcmp((u8 *)&tag, (u8 *)&req->msg->timestamp.tag, sizeof(tag)))
      return 1;
  }

  // H_i := Hash(H_i || msg.timestamp)
  if (crypto_generichash_blake2b_update(H_state, (u8 *)&req->msg->timestamp,
                                        sizeof(req->msg->timestamp)))
    return 1;

  return 0;
}

int nik_handshake_final(NIK_HandshakeState *state, NIK_TxKeys *keys,
                        bool initiator) {
  u8 *C = state->C;

  CryptoKxTx *send = &keys->send;
  CryptoKxTx *recv = &keys->recv;
  if (!initiator) {
    send = &keys->recv;
    recv = &keys->send;
  }

  // (T_send, T_recv) := KDF2(C, e)
  {
    // T0 = HMAC(C, e)
    u8 T0[crypto_kdf_KEYBYTES];
    u8 e[32] = {0};
    if (crypto_generichash_blake2b(T0, sizeof(T0), e, sizeof(e), C,
                                   NIK_CHAIN_SZ))
      return 1;
    // T1 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key((u8 *)send, sizeof(keys->send), 1,
                                   NIK_KDF_CTX, T0))
      return 1;
    // T2 = HMAC(T0, 1)
    if (crypto_kdf_derive_from_key((u8 *)recv, sizeof(keys->recv), 2,
                                   NIK_KDF_CTX, T0))
      return 1;
  }

  memset(state->C, 0, NIK_CHAIN_SZ);
  memset((u8 *)&state->E, 0, sizeof(state->E));

  keys->send_n = 0;
  keys->recv_n = 0;

  return 0;
}

u64 nik_sendmsg_sz(u64 len) { return sizeof(NIK_MsgHeader) + len + len % 16; }

int nik_msg_send(NIK_TxKeys *keys, Str payload, Str send) {
  if (nik_sendmsg_sz(payload.len) != send.len) return 1;
  memset(send.buf, 0, send.len);

  NIK_MsgHeader *header = (NIK_MsgHeader *)send.buf;
  u8 *crypt = (u8 *)(send.buf + sizeof(NIK_MsgHeader));
  u64 payload_len = send.len - sizeof(NIK_MsgHeader);
  memcpy(crypt, payload.buf, payload.len);
  header->payload_len = payload.len;

  header->type = NIK_Msg_Data;
  // TODO header->receiver = ...
  header->counter = keys->send_n++;

  u8 nonce[crypto_box_NONCEBYTES] = {0};
  *(u64 *)nonce = header->counter;
  if (crypto_aead_chacha20poly1305_encrypt_detached(
          crypt, (u8 *)&header->tag, 0, crypt, payload_len,
          (u8 *)&header->payload_len, sizeof(header->payload_len), 0, nonce,
          (u8 *)&keys->send))
    return 1;

  return 0;
}

int nik_msg_recv(NIK_TxKeys *keys, Str *msg) {
  NIK_MsgHeader *header = (NIK_MsgHeader *)msg->buf;
  u8 *crypt = (u8 *)(msg->buf + sizeof(NIK_MsgHeader));
  u64 crypt_len = msg->len - sizeof(NIK_MsgHeader);

  if (header->type != NIK_Msg_Data)
    return 1;
  // TODO: check receiver
  // TODO: check counter
  u8 nonce[crypto_box_NONCEBYTES] = {0};
  *(u64 *)nonce = header->counter;
  if (crypto_aead_chacha20poly1305_decrypt_detached(
          msg->buf, 0, crypt, crypt_len, (u8 *)&header->tag,
          (u8 *)&header->payload_len, sizeof(header->payload_len), nonce,
          (u8 *)&keys->recv))
    return 1;

  msg->len = header->payload_len;
  return 0;
}
