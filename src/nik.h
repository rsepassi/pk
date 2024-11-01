// NIK is a Noise IK implementation.
// WIP, see TODO below.
//
// Implementation based on Wireguard's Noise IK construction:
// * https://www.wireguard.com/protocol/
// * https://www.wireguard.com/papers/wireguard.pdf
//   Copied at doc/wireguard.pdf
//
// Differences from the Wireguard implementation:
// * In HandshakeMsg1, we use msg.static := AEAD(k, 0, Hash(S_pub_i), H_i)
//   (instead of AEAD(k, 0, S_pub_i, H_i)), as suggested by Donenfeld in the
//   Wireguard technical paper.
// * We use blake2b (instead of blake2s) as hash function.
//
// The low-level API does no dynamic memory allocation.
// libsodium provides all cryptographic primitives, except for HMAC
// which is constructed from libsodium's blake2b. See hmac_blake2b in nik.c
//
// Impl TODO:
// * mac2 + CookieReply message
// * Allow providing 256-bit PSK
// * High-level API, state management
//   * Timers, limits
//   * Counter history and validation
//   * Handshake reset
//   * Keepalives
//   * etc
//
// Optimization TODO:
// * Precompute initial chaining key and hash state (per peer)

#include "crypto.h"

#define NIK_CHAIN_SZ 32
#define NIK_TIMESTAMP_SZ 12

typedef enum {
  NIK_OK = 0,
  NIK_Error,
  NIK_Status_HandshakeRefresh,
} NIK_Status;

// NIK Message types
typedef enum {
  NIK_Msg_NONE,
  NIK_Msg_I2R,
  NIK_Msg_R2I,
  NIK_Msg_CookieReply,
  NIK_Msg_Data,
} NIK_MsgType;

// NIK Message 1: Initiator to Responder
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

// NIK Message 2: Responder to Initiator
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

// NIK data message
// With an authenticated length
typedef struct __attribute((packed)) {
  u8 type;
  u8 reserved[3];
  u32 receiver;
  u64 counter;
  CryptoAuthTag tag;
  u64 payload_len;
} NIK_MsgHeader;

// NIK state structs

// Static key exchange keys
typedef struct {
  CryptoKxPK *pk;
  CryptoKxSK *sk;
} NIK_Keys;

// Per-peer transfer state
typedef struct {
  CryptoKxTx send;
  CryptoKxTx recv;
  u64 send_n;
  u64 recv_n;
  u32 sender;
  u32 receiver;
  u64 recv_max_counter;
} NIK_TxState;

typedef struct {
  NIK_Keys *keys;
  CryptoKxPK *bob;
} NIK_HandshakeKeys;

typedef struct {
  u32 sender;
  u32 receiver;
  u8 chaining_key[NIK_CHAIN_SZ];
  crypto_generichash_blake2b_state hash;
  CryptoKxSK ephemeral_sk;
  CryptoKxPK ephemeral_pk;
} NIK_HandshakeState;

// Low-level handshake API
// Initiator sends HandshakeMsg1
NIK_Status nik_handshake_init(const NIK_HandshakeKeys keys,
                              NIK_HandshakeState *state,
                              NIK_HandshakeMsg1 *msg);
// Responder checks HandshakeMsg1
NIK_Status nik_handshake_init_check(const NIK_HandshakeKeys keys,
                                    const NIK_HandshakeMsg1 *msg,
                                    NIK_HandshakeState *state);
// Responder sends HandshakeMsg2
NIK_Status nik_handshake_respond(const NIK_HandshakeKeys keys,
                                 const NIK_HandshakeMsg1 *msg1,
                                 NIK_HandshakeState *state,
                                 NIK_HandshakeMsg2 *msg2);
// Initiator checks HandshakeMsg2
NIK_Status nik_handshake_respond_check(const NIK_HandshakeKeys keys,
                                       const NIK_HandshakeMsg2 *msg,
                                       NIK_HandshakeState *state);
// Handshake is finalized and TxState populated
NIK_Status nik_handshake_final(NIK_HandshakeState *state, NIK_TxState *keys,
                               bool initiator);

// Low-level send/recv API
u64 nik_sendmsg_sz(u64 len);
NIK_Status nik_msg_send(NIK_TxState *state, Bytes payload, Bytes send);
NIK_Status nik_msg_recv(NIK_TxState *state, Bytes *msg);

// High-level API

typedef struct {
  Allocator alloc;
  const NIK_Keys *keys;
} NIK;

// Initialize NIK.
NIK_Status nik_init(NIK *nik, Allocator alloc, const NIK_Keys *keys);

// Send payload to peer.
//
// send must have len nik_sendmsg_sz(payload.len).
// send will be populated with the message.
NIK_Status nik_send(NIK *nik, const CryptoKxPK *peer, const Bytes payload,
                    Bytes send);

// Receive message.
//
// peer will be populated with the key of the peer who sent the message.
// recvd will be populated with the message.
NIK_Status nik_recv(NIK *nik, CryptoKxPK *peer, Str *recvd);
