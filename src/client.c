// vendor deps
#include "argparse.h"
#include "libbase58.h"
#include "lmdb.h"
#include "minicoro.h"
#include "taia.h"
#include "uv.h"

// lib
#include "getpass.h"
#include "log.h"
#include "stdtypes.h"
#include "uvco.h"

// src
#include "crypto.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_PW_LEN 2048

// Global event loop
uv_loop_t *loop;

// Some constant data
char *A_to_B_message = "hello world";
char *A_seed_hex =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char *B_seed_hex =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

void bytes_from_hex(Str s, u8 *out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char *)s.buf, s.len, 0, 0, 0);
}

// Printing
void phex(char *tag, u8 *b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i)
    printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8 *)&(k), sizeof(k))

bool libb58_sha256_impl(void *out, const void *msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}

// Wireguard-lifted Noise IK: "the tunnel simply works"
// * Authenticated key exchange
// * Avoids key-compromise impersonation
// * Avoids replay attacks
// * Provides perfect forward secrecy
// * Hides identity of static public keys
// * Resists denial of service attacks
//
//
// No dynamic memory allocation (Section 7)
//
// Post-quantum option: additional pre-shared 256-bit symmetric encryption key
//
// 4 message types:
// 1. Handshake initiation
// 2. Handshake response
// 3. Encrypted cookie
// 4. Encapsualted encrypted packet
//
// State:
// peers[]
// peer_idx: u32
// my_pk, my_sk
// peer_pk
// eph_pk, eph_sk
// psk: zeros[32]
//
// H hash result, C chaining key
// T_send T_recv transport data symmetric key
// N_send N_recv transport data message nonce
#define NIK_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b"
#define NIK_IDENTIFIER "xos WireGuard v1"
#define NIK_KDF_CTX "wgikkdf1"
#define NIK_CHAIN_SZ 32
#define NIK_TIMESTAMP_SZ 12

// Noise IK Messages
// BREAKING CHANGES
// * In Msg1, We use msg.static := AEAD(k, 0, Hash(S_pub_i), H_i) (instead of
//   AEAD(k, 0, S_pub_i, H_i)).
// * We use blake2b (instead of blake2s)

// Noise IK Message types
typedef enum {
  NIK_Msg_I2R = 1,
  NIK_Msg_R2I = 2,
  NIK_Msg_CookieReply = 3,
  NIK_Msg_Data = 4,
} NIK_MsgType;

// Noise IK Message 1: Initiator to Responder
typedef struct __attribute__((packed)) {
  u8 type;
  u8 reserved[3];
  u32 sender;
  CryptoKxPK ephemeral;
  struct {
    CryptoKxPK key;
    CryptoAuthTag tag;
  } statik;
  struct {
    u8 timestamp[NIK_TIMESTAMP_SZ];
    CryptoAuthTag tag;
  } timestamp;
  CryptoAuthTag mac1;
  CryptoAuthTag mac2;
} NIK_HandshakeMsg1;

// Noise IK Message 2: Responder to Initiator
typedef struct __attribute__((packed)) {
  u8 type;
  u8 reserved[3];
  u32 sender;
  u32 receiver;
  CryptoKxPK ephemeral;
  CryptoAuthTag empty;
  CryptoAuthTag mac1;
  CryptoAuthTag mac2;
} NIK_HandshakeMsg2;

// Noise IK data message
// With an authenticated length
typedef struct __attribute((packed)) {
  u8 type;
  u8 reserved[3];
  u32 receiver;
  u64 counter;
  CryptoAuthTag tag;
  u64 len;
} NIK_MsgHeader;

// Noise IK state structs

typedef struct {
  CryptoKxPK pk;
  CryptoKxSK sk;
} NIK_Keys;

typedef struct {
  CryptoKxTx send;
  u64 send_n;
  CryptoKxTx recv;
  u64 recv_n;
} NIK_TxKeys;

typedef struct {
  NIK_Keys *keys;
  CryptoKxPK *bob;
} NIK_HandshakeKeys;

typedef struct {
  u8 C[NIK_CHAIN_SZ];
  crypto_generichash_blake2b_state H;
  CryptoKxSK E;
} NIK_HandshakeState;

typedef struct {
  // TODO: rm these from msg1 and rm msg1 from this struct
  // * sender
  // * ephemeral pk
  NIK_HandshakeMsg1 *msg1;
  NIK_HandshakeMsg2 *msg2;
  NIK_HandshakeKeys keys;
} NIK_InitiatorHandshakeRequest;

typedef struct {
  NIK_HandshakeMsg1 *msg;
  NIK_HandshakeKeys keys;
} NIK_ResponderHandshakeRequest;

int nik_dh_kdf2(const u8 *C, const CryptoKxPK *pk, const CryptoKxSK *sk,
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
  CryptoKxPK *S_pub_i = &req->keys.keys->pk;
  CryptoKxSK *S_priv_i = &req->keys.keys->sk;

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
  if (nik_dh_kdf2(C_i, &req->keys.keys->pk, &req->keys.keys->sk,
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
  CryptoKxPK *S_pub_r = &req->keys.keys->pk;
  CryptoKxSK *S_priv_r = &req->keys.keys->sk;

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

int nik_keys_kx_from_seed(const CryptoSeed *seed, NIK_Keys *out) {
  CryptoSignPK pk;
  CryptoSignSK sk;
  if (crypto_sign_seed_keypair((u8 *)&pk, (u8 *)&sk, (u8 *)seed))
    return 1;

  if (crypto_sign_ed25519_pk_to_curve25519((u8 *)&out->pk, (u8 *)&pk))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8 *)&out->sk, (u8 *)&sk))
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

u64 noiseik_sendmsg_sz(u64 len) {
  return sizeof(NIK_MsgHeader) + len + len % 16;
}

int noiseik_msg_send(NIK_TxKeys *keys, Str payload, Str send) {
  memset(send.buf, 0, send.len);

  NIK_MsgHeader *header = (NIK_MsgHeader *)send.buf;
  u8 *crypt = (u8 *)(send.buf + sizeof(NIK_MsgHeader));
  u64 payload_len = send.len - sizeof(NIK_MsgHeader);
  memcpy(crypt, payload.buf, payload.len);
  header->len = payload.len;

  header->type = NIK_Msg_Data;
  // TODO header->receiver = ...
  header->counter = keys->send_n++;

  u8 nonce[crypto_box_NONCEBYTES] = {0};
  *(u64 *)nonce = header->counter;
  if (crypto_aead_chacha20poly1305_encrypt_detached(
          crypt, (u8 *)&header->tag, 0, crypt, payload_len, (u8 *)&header->len,
          sizeof(header->len), 0, nonce, (u8 *)&keys->send))
    return 1;

  return 0;
}

int noiseik_msg_recv(NIK_TxKeys *keys, Str *msg) {
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
          msg->buf, 0, crypt, crypt_len, (u8 *)&header->tag, (u8 *)&header->len,
          sizeof(header->len), nonce, (u8 *)&keys->recv))
    return 1;

  msg->len = header->len;
  return 0;
}

int demo_noiseik(int argc, const char **argv) {
  NIK_Keys keys_i;
  {
    Str A_seed_str = str_from_c(A_seed_hex);
    CryptoSeed A_seed;
    sodium_hex2bin((u8 *)&A_seed, sizeof(A_seed), (char *)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &keys_i));
  }

  NIK_Keys keys_r;
  {
    Str B_seed_str = str_from_c(B_seed_hex);
    CryptoSeed B_seed;
    sodium_hex2bin((u8 *)&B_seed, sizeof(B_seed), (char *)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &keys_r));
  }

  // I
  LOG("i2r");
  NIK_HandshakeState state_i;
  NIK_HandshakeKeys hkeys_i = {&keys_i, &keys_r.pk};
  NIK_InitiatorHandshakeRequest req = {0, 0, hkeys_i};
  NIK_HandshakeMsg1 msg1;
  CHECK0(nik_handshake_init(&req, &state_i, &msg1));
  phex("IC", state_i.C, NIK_CHAIN_SZ);

  // R
  LOG("i2r check");
  NIK_HandshakeState state_r;
  NIK_HandshakeKeys hkeys_r = {&keys_r, &keys_i.pk};
  NIK_ResponderHandshakeRequest rreq = {&msg1, hkeys_r};
  CHECK0(nik_handshake_init_check(&rreq, &state_r));
  phex("RC", state_r.C, NIK_CHAIN_SZ);

  // R
  LOG("r2i");
  NIK_HandshakeMsg2 msg2;
  CHECK0(nik_handshake_respond(&rreq, &state_r, &msg2));
  phex("RC", state_r.C, NIK_CHAIN_SZ);

  // I
  LOG("r2i check");
  NIK_InitiatorHandshakeRequest ireq = {&msg1, &msg2, hkeys_i};
  CHECK0(nik_handshake_respond_check(&ireq, &state_i));
  phex("IC", state_i.C, NIK_CHAIN_SZ);

  // I
  LOG("i derive");
  NIK_TxKeys tx_i;
  CHECK0(nik_handshake_final(&state_i, &tx_i, true));

  // R
  LOG("r derive");
  NIK_TxKeys tx_r;
  CHECK0(nik_handshake_final(&state_r, &tx_r, false));

  // Check that I and R have the same transfer keys
  phex("tx", (u8 *)&tx_i, sizeof(tx_i));
  CHECK0(sodium_memcmp(&tx_i.send, &tx_r.recv, sizeof(tx_i.send)));
  CHECK0(sodium_memcmp(&tx_i.recv, &tx_r.send, sizeof(tx_i.send)));

  // I: Send a message
  Str payload = str_from_c("hello!");
  LOG("send: %.*s", (int)payload.len, payload.buf);
  u64 send_sz = noiseik_sendmsg_sz(payload.len);
  Str send_msg = {.len = send_sz, .buf = malloc(send_sz)};
  CHECK(send_msg.buf);
  CHECK0(noiseik_msg_send(&tx_i, payload, send_msg));

  // R: Receive a message
  CHECK0(noiseik_msg_recv(&tx_r, &send_msg));
  LOG("recv: %.*s", (int)send_msg.len, send_msg.buf);
  CHECK(str_eq(payload, send_msg));

  free(send_msg.buf);

  // todo:
  // cookies: mac1, mac2
  // pick out exactly what's needed from msg1 and msg2
  //  + zero out E pub
  // counter checks
  //   We use a sliding window to keep track of received message counters, in
  //   which we keep track of the greatest counter received, as well as a
  //   window of prior messages received, checked only after having verified
  //   the authentication tag, using the algorithm detailed by appendix C of
  //   RFC2401 [14] or by RFC6479 [26], which uses a larger bitmap while
  //   avoiding bitshifts, enabling more extreme packet reordering that may
  //   occur on multi-core systems.
  // Timers

  return 0;
}

int demo_kv(int argc, const char **argv) {
  // get or put
  enum { KvGet, KvPut } cmd;
  MDB_val user_key;
  MDB_val user_val;
  {
    CHECK(argc >= 4, "usage: demo-kv kvfolder {get,put} key [value]");
    user_key.mv_data = (void *)argv[3];
    user_key.mv_size = strlen(user_key.mv_data);
    if (!strcmp(argv[2], "get")) {
      cmd = KvGet;
      CHECK(argc == 4);
    } else if (!strcmp(argv[2], "put")) {
      cmd = KvPut;
      CHECK(argc == 5);
      user_val.mv_data = (void *)argv[4];
      user_val.mv_size = strlen(user_val.mv_data);
    } else {
      CHECK(false, "must specify get or put");
    }
    (void)cmd;
  }

  // Open/create KV
  MDB_env *kv;
  MDB_dbi db;
  MDB_txn *txn;
  MDB_txn *rtxn;
  {
    const char *kv_path = argv[1];
    LOG("kv=%s", kv_path);

    // Check that directory exists
    uv_fs_t req;
    CHECK0(uvco_fs_stat(loop, &req, kv_path), "kv path must be a directory: %s",
           kv_path);
    CHECK(S_ISDIR(req.statbuf.st_mode), "kv path must be a directory: %s",
          kv_path);
    uv_fs_req_cleanup(&req);

    mode_t kv_mode = S_IRUSR | S_IWUSR | S_IRGRP; // rw-r-----
    CHECK0(mdb_env_create(&kv));
    CHECK0(mdb_env_open(kv, kv_path, MDB_NOLOCK, kv_mode));
    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_dbi_open(txn, 0, MDB_CREATE, &db));
    CHECK0(mdb_txn_commit(txn));
  }

  // Ask for password
  char *pw = malloc(MAX_PW_LEN);
  sodium_mlock(pw, MAX_PW_LEN);
  ssize_t pw_len;
  {
    fprintf(stderr, "pw > ");
    if (1) {
      pw_len = getpass(pw, MAX_PW_LEN);
      CHECK(pw_len >= 0);
    } else {
      pw = "asdfasdf";
      pw_len = strlen(pw);
    }
  }

  // If it's a fresh db:
  // * Store the password hash
  // * Generate a salt
  // Else:
  // * Validate the password
  // * Lookup the salt
  u8 salt[crypto_pwhash_SALTBYTES];
  {
    CHECK0(mdb_txn_begin(kv, 0, MDB_RDONLY, &rtxn));
    MDB_val salt_key = {6, "__salthash"};
    MDB_val salt_val;
    int rc = mdb_get(rtxn, db, &salt_key, &salt_val);
    mdb_txn_reset(rtxn);
    if (rc == MDB_NOTFOUND) {
      LOG("fresh kv store");
      u8 pwhash_and_salt[crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES];

      // Create a random salt
      randombytes_buf(pwhash_and_salt, crypto_pwhash_SALTBYTES);
      memcpy(salt, pwhash_and_salt, crypto_pwhash_SALTBYTES);

      // Hash the password
      u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
      u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
      CHECK0(
          crypto_pwhash_str((char *)(pwhash_and_salt + crypto_pwhash_SALTBYTES),
                            pw, pw_len, opslimit, memlimit));

      // Insert in kv
      salt_val.mv_size = crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES;
      salt_val.mv_data = pwhash_and_salt;
      CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
      CHECK0(mdb_put(txn, db, &salt_key, &salt_val, 0));
      CHECK0(mdb_txn_commit(txn));
    } else {
      CHECK0(rc, "failed to read database");
      CHECK(salt_val.mv_size ==
            crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES);

      // Copy out salt
      memcpy(salt, salt_val.mv_data, crypto_pwhash_SALTBYTES);

      // Verify password hash
      CHECK0(
          crypto_pwhash_str_verify(
              (char *)(salt_val.mv_data + crypto_pwhash_SALTBYTES), pw, pw_len),
          "wrong password");
    }
  }

  // Derive the key
  u8 key[crypto_secretbox_KEYBYTES];
  {
    u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    CHECK0(crypto_pwhash(key, sizeof(key), pw, pw_len, salt, opslimit, memlimit,
                         crypto_pwhash_ALG_ARGON2ID13));
  }

  // Password no longer needed
  sodium_munlock(pw, MAX_PW_LEN);
  free(pw);

  // Encrypt the key with a nonce derived from the key and db salt
  u64 ekey_len = user_key.mv_size + crypto_secretbox_MACBYTES;
  u8 *ekey = malloc(ekey_len);
  {
    u8 key_nonce[crypto_secretbox_NONCEBYTES];
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, 0, 0, sizeof(key_nonce));
    crypto_generichash_blake2b_update(&state, user_key.mv_data,
                                      user_key.mv_size);
    crypto_generichash_blake2b_update(&state, salt, sizeof(salt));
    crypto_generichash_blake2b_final(&state, key_nonce, sizeof(key_nonce));
    CHECK0(crypto_secretbox_easy(ekey, user_key.mv_data, user_key.mv_size,
                                 key_nonce, key));
    user_key.mv_data = ekey;
    user_key.mv_size = ekey_len;
  }

  if (cmd == KvGet) {
    CHECK0(mdb_txn_begin(kv, 0, MDB_RDONLY, &rtxn));
    int rc = mdb_get(rtxn, db, &user_key, &user_val);
    if (rc == MDB_NOTFOUND) {
      LOG("key not found");
      return 1;
    } else {
      CHECK0(rc, "failed to read database");
      u64 decrypted_len = user_val.mv_size - crypto_secretbox_NONCEBYTES -
                          crypto_secretbox_MACBYTES;
      u8 *decrypted = malloc(decrypted_len);
      CHECK0(crypto_secretbox_open_easy(
                 decrypted, user_val.mv_data + crypto_secretbox_NONCEBYTES,
                 user_val.mv_size - crypto_secretbox_NONCEBYTES,
                 user_val.mv_data, key),
             "failed to decrypt");
      printf("%.*s\n", (int)decrypted_len, decrypted);
      free(decrypted);
    }
  } else if (cmd == KvPut) {
    u64 encrypted_len = user_val.mv_size + crypto_secretbox_NONCEBYTES +
                        crypto_secretbox_MACBYTES;
    u8 *encrypted = malloc(encrypted_len);
    randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
    CHECK0(crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES,
                                 user_val.mv_data, user_val.mv_size, encrypted,
                                 key));
    user_val.mv_data = encrypted;
    user_val.mv_size = encrypted_len;

    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_put(txn, db, &user_key, &user_val, 0));
    CHECK0(mdb_txn_commit(txn));

    free(encrypted);
  } else
    CHECK(false);

  free(ekey);
  mdb_env_close(kv);
  return 0;
}

int demo_x3dh(int argc, const char **argv) {
  // Alice seed
  Str A_seed_str = str_from_c(A_seed_hex);
  CHECK(A_seed_str.len == 64, "got length %d", (int)A_seed_str.len);
  CryptoSeed A_seed;
  sodium_hex2bin((u8 *)&A_seed, sizeof(A_seed), (char *)A_seed_str.buf,
                 A_seed_str.len, 0, 0, 0);
  pcrypt(A_seed);

  // Bob seed
  Str B_seed_str = str_from_c(B_seed_hex);
  CHECK(B_seed_str.len == 64, "got length %d", (int)B_seed_str.len);
  CryptoSeed B_seed;
  sodium_hex2bin((u8 *)&B_seed, sizeof(B_seed), (char *)B_seed_str.buf,
                 B_seed_str.len, 0, 0, 0);
  pcrypt(B_seed);

  // Alice init
  CryptoUserState A_sec;
  CHECK(crypto_seed_new_user(&A_seed, &A_sec) == 0);

  // Bob init
  CryptoUserState B_sec;
  CHECK(crypto_seed_new_user(&B_seed, &B_sec) == 0);

  // Alice's message to Bob
  Str A_msg_buf;
  {
    Str plaintxt = str_from_c(A_to_B_message);
    printf("plaintxt=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    A_msg_buf.len = crypto_x3dh_first_msg_len(plaintxt.len);
    A_msg_buf.buf = malloc(A_msg_buf.len);
    CHECK(crypto_x3dh_first_msg(&A_sec, &B_sec.pub, plaintxt, &A_msg_buf) == 0);
  }

  phex("msg", A_msg_buf.buf, A_msg_buf.len);

  // Bob receives Alice's message
  {
    Str ciphertxt;
    CryptoX3DHFirstMessageHeader *header;
    CHECK(crypto_x3dh_first_msg_parse(A_msg_buf, &header, &ciphertxt) == 0);

    Str plaintxt;
    plaintxt.len = crypto_plaintxt_len(ciphertxt.len);
    plaintxt.buf = malloc(plaintxt.len);

    CHECK(crypto_x3dh_first_msg_recv(&B_sec, header, ciphertxt, &plaintxt) ==
          0);

    printf("decrypted=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    CHECK(plaintxt.len == strlen(A_to_B_message));
    CHECK(sodium_memcmp(plaintxt.buf, A_to_B_message, strlen(A_to_B_message)) ==
          0);

    free(plaintxt.buf);
  }

  free(A_msg_buf.buf);

  // TODO:
  // * Nonce needs to be incremented per session key or random
  // * Rotate pre-shared key
  // * One-time prekeys (and possibly other replay mitigations)
  // * Double ratchet

  // Lookup registrar for destination key from directory
  // DirectoryResult dir = pk_directory_lookup(ctx, pk)

  // Lookup mailbox for destination key from registrar
  // RecordResult rec = pk_registrar_record_lookup(ctx, dir.registrar, pk,
  // RecordMailbox);

  // Package message for mailbox

  // Send message to mailbox
  return 0;
}

int demo_getkey(Str seed_str, CryptoSignPK *pk, CryptoSignSK *sk) {
  CryptoSeed seed;
  sodium_hex2bin((u8 *)&seed, sizeof(seed), (char *)seed_str.buf, seed_str.len,
                 0, 0, 0);
  if (crypto_sign_seed_keypair((u8 *)pk, (u8 *)sk, (u8 *)&seed))
    return 1;
  return 0;
}

int demo_b58(int argc, const char **argv) {
  b58_sha256_impl = libb58_sha256_impl;

  Str hex = str_from_c("165a1fc5dd9e6f03819fca94a2d89669469667f9a0");
  u8 bin[21];
  bytes_from_hex(hex, bin, sizeof(bin));
  phex("orig", bin, sizeof(bin));

  char b58[42];
  size_t b58_len = sizeof(b58);
  CHECK(b58check_enc(b58, &b58_len, bin[0], &bin[1], sizeof(bin) - 1));

  LOG("b58c=%s", b58);

  u8 bin2[25];
  size_t bin2_len = sizeof(bin2);
  CHECK(b58tobin(bin2, &bin2_len, b58, b58_len - 1));
  phex("deco", bin2, bin2_len);

  CHECK(b58check(bin2, bin2_len, b58, b58_len) == 22);
  CHECK0(memcmp(bin2, bin, bin2_len - 4));

  return 0;
}

static const char *const usages[] = {
    "pk [options] [cmd] [args]\n\n    Commands:"
    "\n      - demo-x3dh"
    "\n      - demo-kv"
    "\n      - demo-noiseik-client"
    "\n      - demo-noiseik-server",
    "\n      - demo-b58",
    NULL,
};

struct cmd_struct {
  const char *cmd;
  int (*fn)(int, const char **);
};

static struct cmd_struct commands[] = {
    {"demo-x3dh", demo_x3dh},
    {"demo-kv", demo_kv},
    {"demo-noiseik", demo_noiseik},
    {"demo-b58", demo_b58},
};

typedef struct {
  int argc;
  const char **argv;
} MainCoroCtx;

void coro_exit(u8 code) { mco_push(mco_running(), &code, 1); }

void main_coro(mco_coro *co) {
  MainCoroCtx *ctx = (MainCoroCtx *)mco_get_user_data(co);

  int argc = ctx->argc;
  const char **argv = ctx->argv;

  struct argparse argparse;
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_END(),
  };
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  if (argc < 1) {
    argparse_usage(&argparse);
    return coro_exit(1);
  }

  struct cmd_struct *cmd = NULL;
  for (int i = 0; i < ARRAY_SIZE(commands); i++) {
    if (!strcmp(commands[i].cmd, argv[0])) {
      cmd = &commands[i];
      break;
    }
  }

  if (!cmd) {
    argparse_usage(&argparse);
    return coro_exit(1);
  }

  return coro_exit(cmd->fn(argc, argv));
}

#define MAIN_STACK_SIZE 1 << 21

void *mco_alloc(size_t size, void *udata) {
  MainCoroCtx *ctx = (MainCoroCtx *)udata;
  (void)ctx;
  (void)size;
  return calloc(1, size);
}

void mco_dealloc(void *ptr, size_t size, void *udata) {
  MainCoroCtx *ctx = (MainCoroCtx *)udata;
  (void)ctx;
  (void)size;
  return free(ptr);
}

int main(int argc, const char **argv) {
  LOG("hello");

  // libsodium init
  CHECK(crypto_init() == 0);

  // libuv init
  loop = malloc(sizeof(uv_loop_t));
  CHECK(loop);
  uv_loop_init(loop);

  // coro init
  MainCoroCtx ctx = {argc, argv};
  mco_desc desc = mco_desc_init(main_coro, MAIN_STACK_SIZE);
  desc.allocator_data = &ctx;
  desc.alloc_cb = mco_alloc;
  desc.dealloc_cb = mco_dealloc;
  desc.user_data = &ctx;
  mco_coro *co;
  CHECK(mco_create(&co, &desc) == MCO_SUCCESS);

  // run
  CHECK(mco_resume(co) == MCO_SUCCESS);
  if (mco_status(co) == MCO_SUSPENDED)
    uv_run(loop, UV_RUN_DEFAULT);

  u8 rc = 0;
  if (mco_get_storage_size(co) > 0)
    mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  uv_loop_close(loop);
  free(loop);

  LOG("goodbye (code=%d)", rc);
  return rc;
}
