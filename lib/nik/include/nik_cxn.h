// Persistent key-rotating kept-alive NIK connection between 2 peers.
#pragma once

#include "nik.h"

#ifndef NIK_LIMIT_MAX_OUTGOING
#define NIK_LIMIT_MAX_OUTGOING 128
#endif

#define NIK_LIMIT_REKEY_AFTER_MESSAGES (UINT64_C(1) << 60)
#define NIK_LIMIT_REJECT_AFTER_MESSAGES (UINT64_MAX - (UINT64_C(1) << 13) - 1)
#define NIK_LIMIT_REKEY_AFTER_SECS 120
#define NIK_LIMIT_REJECT_AFTER_SECS 180
#define NIK_LIMIT_REKEY_ATTEMPT_SECS 90
#define NIK_LIMIT_REKEY_TIMEOUT_SECS 5
#define NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS 10
// Unused, but kept if/when we implement cookies.
// #define NIK_LIMIT_COOKIE_REFRESH_SECS 120

typedef enum {
  NIK_Cxn_OK = 0,
  NIK_Cxn_Error,
  NIK_Cxn_Status_MsgReady,
  NIK_Cxn_Status_QFull,
} NIK_Cxn_Status;

// Key rotation state machine
//
// Initiator states:
// 1. Null
// 2. StartWait: Waiting to start (jitter + throttle)
// 3. I2RReady: Initial handshake message ready to send
// 4. R2IWait: Waiting for handshake response
// 5. Success
// 6. Fail
//
// Transitions:
// 1 -> 2: timeout triggers
// 1 -> 3: max messages hit
// 2 -> 3: jitter+throttle done
// 3 -> 4: send I2R message
// 4 -> 3: timer exceeded, retry
// 4 -> 5: received R2I, key rotated
// 4 -> 6: timeout expired
//
// Responder states:
// 1. Null
// 2. R2IReady: Response handshake message ready to send
// 3. DataWait: Waiting for data message
// 4. Success
// 5. Fail
//
// Transitions:
// 1 -> 2: received I2R, computed R2I
// 2 -> 3: send R2I
// 3 -> 4: received data, key rotated
// 3 -> 5: expired
typedef enum {
  NIK_CxnHState_Null,
  NIK_CxnHState_I_StartWait, // triggered, but waiting to initiate
  NIK_CxnHState_I_I2RReady,  // Handshake init ready to send
  NIK_CxnHState_I_R2IWait,   // waiting for handshake response
  NIK_CxnHState_R_R2IReady,  // Handshake response ready to send
  NIK_CxnHState_R_DataWait,  // responder waiting for first data packet
} NIK_Cxn_HandshakeState;

typedef struct {
  union {
    struct {
      NIK_Handshake handshake;
      NIK_HandshakeMsg1 msg;
      u64 handshake_start_time;
    } initiator;
    struct {
      NIK_HandshakeMsg2 msg;
    } responder;
  };
} NIK_Cxn_Handshake;

typedef enum {
  NIK_Cxn_Event_NONE,
  NIK_Cxn_Event_Data,
  NIK_Cxn_Event_Error,
} NIK_Cxn_Event;

typedef struct NIK_Cxn_s NIK_Cxn;
typedef void (*NIK_CxnCb)(NIK_Cxn *cxn, void *userdata, NIK_Cxn_Event e,
                          Bytes data, u64 now);

struct NIK_Cxn_s {
  // Connection keys
  NIK_Keys keys;
  // NIK identifier
  u32 id;

  // User callback and context
  NIK_CxnCb cb;
  void *userdata;

  // Active sessions
  NIK_Session current;
  NIK_Session prev;
  NIK_Session next;
  u64 current_start_time;
  u64 prev_start_time;
  u64 next_start_time;

  // In-flight handshake state
  NIK_Cxn_HandshakeState handshake_state;
  NIK_Cxn_Handshake handshake;

  // Max observed time
  u64 maxtime;
  // Time of the last data/keepalive message sent and received
  u64 last_send_time;
  u64 last_recv_time;
  u64 last_keepalive_send_time;
  u64 last_keepalive_recv_time;
  // Time the last handshake initiation message was sent
  u64 last_handshake_init_time;
  // Max timestamp received in a handshake initiation message
  u8 max_handshake_timestamp[NIK_TIMESTAMP_SZ];

  // Outgoing message queue. Only used for user messages.
  Bytes outgoing[NIK_LIMIT_MAX_OUTGOING];
  usize outgoing_head;
  usize outgoing_next;
};

// Initializes a NIK_Cxn object for the given peer, as initiator or responder.
// cb will be used to deliver NIK events and messages.
void nik_cxn_init(NIK_Cxn *cxn, NIK_Keys keys, NIK_CxnCb cb, void *userdata);
// nik_handshake_init_check must have already been run.
void nik_cxn_init_responder(NIK_Cxn *cxn, NIK_Keys keys, NIK_Handshake *state,
                            const NIK_HandshakeMsg1 *msg1, NIK_CxnCb cb,
                            void *userdata, u64 now);

// Deinitializes a NIK_Cxn.
void nik_cxn_deinit(NIK_Cxn *cxn);

// Enqueues a message for eventual delivery via nik_cxn_outgoing.
// Returns NIK_Cxn_Status_QFull if the outgoing message queue is full.
// TODO: document lifetime of payload
NIK_Cxn_Status nik_cxn_enqueue(NIK_Cxn *cxn, Bytes payload);

// Returns the duration in milliseconds before the NIK_Cxn needs to send out
// a message.
u64 nik_cxn_get_next_wait_delay(NIK_Cxn *cxn, u64 now, u64 maxdelay);

// Provides an incoming network message to the NIK_Cxn.
void nik_cxn_incoming(NIK_Cxn *cxn, Bytes msg, u64 now);

// Retrieves outgoing messages from the NIK_Cxn.
// Returns NIK_Cxn_Status_MsgReady if msg needs to be sent out.
// Returns NIK_OK when there are no messages to be delivered.
// Caller owns the returned memory in msg, which is allocated internally.
NIK_Cxn_Status nik_cxn_outgoing(NIK_Cxn *cxn, Bytes *msg, u64 now);
