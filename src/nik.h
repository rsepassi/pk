// NIK is a Wireguard-like Noise IK implementation.
//
// See https://www.wireguard.com/papers/wireguard.pdf
// Copied at doc/wireguard.pdf
//
// Differences from the Wireguard implementation:
// * In HandshakeMsg1, We use msg.static := AEAD(k, 0, Hash(S_pub_i), H_i)
//   (instead of AEAD(k, 0, S_pub_i, H_i)), as suggested by Donenfeld in the
//   Wireguard technical paper.
// * We use blake2b (instead of blake2s) as hash function.
// * The optional 256-bit symmetric encryption key is always 0. This may
//   change in the future.
//
// The low-level API does no dynamic memory allocation.
// libsodium provides all cryptographic primitives.
//
// Implementation is not yet complete.
// TODO:
// * Track sender/receiver ids
// * Set header->receiver in nik_msg_send
// * Check header->receiver in nik_msg_recv
// * Check header->counter in nik_msg_recv
// * Fill in mac1, mac2
// * Implement CookieReply message
// * Rm msg1 from NIK_InitiatorHandshakeRequest, it should be thrown out after
//   sending it. It needs to keep sender and ephemeral pk.
// * High-level API

#include "crypto.h"

typedef int NIK_Status;
#define NIK_OK 0
#define NIK_Status_HandshakeRefresh 8

#define NIK_CHAIN_SZ 32
#define NIK_TIMESTAMP_SZ 12

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

// Per-peer transfer keys
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
  NIK_HandshakeMsg1 *msg1;
  NIK_HandshakeMsg2 *msg2;
  NIK_HandshakeKeys keys;
} NIK_InitiatorHandshakeRequest;

typedef struct {
  NIK_HandshakeMsg1 *msg;
  NIK_HandshakeKeys keys;
} NIK_ResponderHandshakeRequest;

// Low-level handshake API
NIK_Status nik_handshake_init(const NIK_InitiatorHandshakeRequest *req,
                              NIK_HandshakeState *state,
                              NIK_HandshakeMsg1 *msg);
NIK_Status nik_handshake_init_check(const NIK_ResponderHandshakeRequest *req,
                                    NIK_HandshakeState *state);
NIK_Status nik_handshake_respond(const NIK_ResponderHandshakeRequest *req,
                                 NIK_HandshakeState *state,
                                 NIK_HandshakeMsg2 *msg);
NIK_Status nik_handshake_respond_check(const NIK_InitiatorHandshakeRequest *req,
                                       NIK_HandshakeState *state);
NIK_Status nik_handshake_final(NIK_HandshakeState *state, NIK_TxKeys *keys,
                               bool initiator);

// Low-level send/recv API
u64 nik_sendmsg_sz(u64 len);
NIK_Status nik_msg_send(NIK_TxKeys *keys, Bytes payload, Bytes send);
NIK_Status nik_msg_recv(NIK_TxKeys *keys, Bytes *msg);

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
