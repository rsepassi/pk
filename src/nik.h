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
//
// Optimization TODO:
// * Precompute initial chaining key and hash state (per peer)

#include "crypto.h"

#define NIK_CHAIN_SZ 32
#define NIK_TIMESTAMP_SZ 12

#define NIK_LIMIT_REKEY_AFTER_MESSAGES (UINT64_C(1) << 60)
#define NIK_LIMIT_REJECT_AFTER_MESSAGES (UINT64_MAX - (UINT64_C(1) << 13) - 1)
#define NIK_LIMIT_REKEY_AFTER_SECS 120
#define NIK_LIMIT_REJECT_AFTER_SECS 180
#define NIK_LIMIT_REKEY_ATTEMPT_SECS 90
#define NIK_LIMIT_REKEY_TIMEOUT_SECS 5
#define NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS 10

typedef enum {
  NIK_OK = 0,
  NIK_Error,
  NIK_Status_SessionRekeyTimer,
  NIK_Status_SessionRekeyMaxmsg,
  NIK_Status_SessionExpired,
  NIK_Status_InternalMsg,
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

typedef u64 CounterHistory;

// Per-peer transfer state
typedef struct {
  CryptoKxTx send;
  CryptoKxTx recv;
  u64 send_n;
  u64 recv_n;
  u32 sender;
  u32 receiver;
  u64 recv_max_counter;
  CounterHistory counter_history;
  u64 start_time;
  u64 last_send_time;
  u64 last_recv_time;
  bool isinitiator;
} NIK_Session;

typedef struct {
  NIK_Keys *keys;
  CryptoKxPK *bob;
} NIK_HandshakeKeys;

typedef struct {
  NIK_HandshakeKeys keys;
  u32 sender;
  u32 receiver;
  u8 chaining_key[NIK_CHAIN_SZ];
  crypto_generichash_blake2b_state hash;
  CryptoKxSK ephemeral_sk;
  CryptoKxPK ephemeral_pk;
  bool initiator;
} NIK_Handshake;

// Low-level handshake API
// Initiator sends HandshakeMsg1
NIK_Status nik_handshake_init(NIK_Handshake *state,
                              const NIK_HandshakeKeys keys,
                              NIK_HandshakeMsg1 *msg);
// Responder checks HandshakeMsg1
NIK_Status nik_handshake_init_check(NIK_Handshake *state,
                                    const NIK_HandshakeKeys keys,
                                    const NIK_HandshakeMsg1 *msg);
// Responder sends HandshakeMsg2
NIK_Status nik_handshake_respond(NIK_Handshake *state,
                                 const NIK_HandshakeMsg1 *msg1,
                                 NIK_HandshakeMsg2 *msg2);
// Initiator checks HandshakeMsg2
NIK_Status nik_handshake_respond_check(NIK_Handshake *state,
                                       const NIK_HandshakeMsg2 *msg);
// Handshake is finalized and Session populated
NIK_Status nik_handshake_final(NIK_Handshake *state, NIK_Session *session,
                               u64 now);

// Low-level send/recv API
u64 nik_sendmsg_sz(u64 len);
NIK_Status nik_msg_send(NIK_Session *session, Bytes payload, Bytes send,
                        u64 now);
NIK_Status nik_msg_recv(NIK_Session *session, Bytes *msg, u64 now);

// Persistent key-rotating kept-alive connection between 2 peers

// CxnSys provides the system functionality that the Cxn needs.
typedef struct {
  void *userctx;
  u64 (*now)(void *userctx);
  void (*sleep)(void *userctx, u64 timeout);
  void (*send)(void *userctx, Bytes timeout);
} NIK_CxnSys;

typedef struct {
  NIK_HandshakeKeys keys;
  NIK_CxnSys sys;

  NIK_Session current;
  NIK_Session prev;
  u64 handshake_initiated_time;
  NIK_Handshake handshake;
  NIK_MsgHeader keepalive;
  u64 rekey_deadline;
  void *keepalive_coro;
  void *rekey_coro;
  void *rekey_waiter;
  u64 last_handshake_sent;
  bool cancelled;
  bool failed;
} NIK_Cxn;

void nik_cxn_init(NIK_Cxn *cxn, NIK_HandshakeKeys keys, NIK_CxnSys sys);
void nik_cxn_deinit(NIK_Cxn *cxn);
NIK_Status nik_cxn_recv(NIK_Cxn *cxn, Bytes *send, u64 now);
NIK_Status nik_cxn_send(NIK_Cxn *cxn, Bytes payload, Bytes send, u64 now);
