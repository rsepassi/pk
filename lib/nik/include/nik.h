// NIK is a Noise IK implementation.
//
// Noise:
// * https://noiseprotocol.org/noise.html
// * http://www.noiseprotocol.org/noise.pdf
//   Copied at doc/noise.pdf
//
// Implementation based on Wireguard's Noise IK construction:
// * https://www.wireguard.com/protocol/
// * https://www.wireguard.com/papers/wireguard.pdf
//   Copied at doc/wireguard.pdf
//
// Differences from the Wireguard implementation:
// * We use blake2b (instead of blake2s) as hash function because it's
//   implemented in libsodium. If this were being used on 32-bit devices
//   blake2s would be better.
// * mac2 + CookieReply is unimplemented for now, but may be implemented in
//   future.
//
// The low-level API does no dynamic memory allocation.
// See nik_cxn.h for connection handling with key rotation and keepalives.
//
// libsodium provides all cryptographic primitives, except for HMAC
// which is constructed from libsodium's blake2b. See hmac_blake2b in nik.c
#pragma once

#include "crypto.h"
#include "nik_hs.h"

#define NIK_TIMESTAMP_SZ 12

// NIK Message types
typedef enum {
  NIK_Msg_NONE,
  NIK_Msg_I2R,
  NIK_Msg_R2I,
  NIK_Msg_CookieReply,
  NIK_Msg_Data,
  NIK_Msg_Keepalive,
  NIK_Msg_MAX = 255,
} NIK_MsgType;

// NIK Handshake Message 1: Initiator to Responder
typedef struct __attribute__((packed)) {
  u8             type;
  u8             reserved[3];
  u32            sender;
  NIK_Handshake1 hs;
  struct {
    u8            timestamp[NIK_TIMESTAMP_SZ];
    CryptoAuthTag tag;
  } timestamp;
  CryptoAuthTag mac1;
} NIK_HandshakeMsg1;

// NIK Handshake Message 2: Responder to Initiator
typedef struct __attribute__((packed)) {
  u8             type;
  u8             reserved[3];
  u32            sender;
  u32            receiver;
  NIK_Handshake2 hs;
  CryptoAuthTag  empty;
  CryptoAuthTag  mac1;
} NIK_HandshakeMsg2;

// NIK data message with an authenticated length
typedef struct __attribute__((packed)) {
  u8            type;
  u8            reserved[3];
  u32           receiver;
  u64           counter;
  CryptoAuthTag tag;
  u16           payload_len;
} NIK_MsgHeader;

// A window of the last 64 messages are kept to prevent replays
typedef u64 CounterHistory;

// Per-peer transfer session state
typedef struct {
  CryptoKxTx     send;
  CryptoKxTx     recv;
  u64            send_n;
  u64            recv_n;
  u32            local_idx;
  u32            remote_idx;
  u64            counter_max;
  CounterHistory counter_history;
  bool           isinitiator;
} NIK_Session;

// State of an ongoing handshake
typedef struct {
  NIK_Keys                         keys;
  u32                              local_idx;
  u32                              remote_idx;
  u8                               chaining_key[NIK_CHAIN_SZ];
  crypto_generichash_blake2b_state hash;
  CryptoKxSK                       ephemeral_sk;
  CryptoKxPK                       ephemeral_pk;
  bool                             initiator;
} NIK_Handshake;

// Low-level handshake API
// Initiator sends HandshakeMsg1
NIK_Status nik_handshake_init(NIK_Handshake* state, const NIK_Keys keys,
                              u32 local_idx, NIK_HandshakeMsg1* msg);
// Responder checks HandshakeMsg1
NIK_Status nik_handshake_init_check(NIK_Handshake* state, const NIK_Keys keys,
                                    NIK_HandshakeMsg1* msg);
// Responder sends HandshakeMsg2
NIK_Status nik_handshake_respond(NIK_Handshake* state, u32 local_idx,
                                 const NIK_HandshakeMsg1* msg1,
                                 NIK_HandshakeMsg2*       msg2);
// Initiator checks HandshakeMsg2
NIK_Status nik_handshake_respond_check(NIK_Handshake*           state,
                                       const NIK_HandshakeMsg2* msg);
// Handshake is finalized and Session populated
NIK_Status nik_handshake_final(NIK_Handshake* state, NIK_Session* session);

// Low-level send/recv API
// Determines the length of an outgoing message given a payload length.
u64 nik_sendmsg_sz(u64 len);
// Encrypts payload into send. send must have length
// nik_sendmsg_sz(payload.len).
NIK_Status nik_msg_send(NIK_Session* session, Bytes payload, Bytes send);
// Decrypts msg in place.
NIK_Status nik_msg_recv(NIK_Session* session, Bytes* msg);
