#pragma once
#include "nik.h"

// Persistent key-rotating kept-alive connection between 2 peers

// Key rotation state machine
//
// Initiator states:
// 1. Null
// 2. Waiting to start (jitter + rekey timeout remainder)
// 3. Initial message ready to send
// 4. Waiting for handshake response
// 5. Success
// 6. Fail
//
// Transitions:
// 1 -> 2: timeout
// 1 -> 3: max messages
// 2 -> 3: delay done
// 3 -> 4: send I2R
// 4 -> 3: timer exceeded, retry
// 4 -> 5: key rotated
// 4 -> 6: expired
//
// Responder states:
// 1. Null
// 2. Response ready to send
// 3. Waiting for data
// 4. Success
// 5. Fail
//
// Transitions:
// 1 -> 2: received I2R, computed R2I
// 2 -> 3: send R2I
// 3 -> 4: done
// 3 -> 5: expired

typedef enum {
  NIK_KR_Null,
  NIK_KR_Error,
  NIK_KR_Success,
  NIK_KR_I_StartWait,
  NIK_KR_I_I2RReady,
  NIK_KR_I_R2IWait,
  NIK_KR_R_R2IReady,
  NIK_KR_R_DataWait,
} NIK_Cxn_KeyRotationState;

typedef struct {
  NIK_HandshakeMsg1 msg;
  u64 handshake_start_time;
} NIK_Cxn_I_KeyRotation;

typedef struct {
  NIK_HandshakeMsg2 msg;
} NIK_Cxn_R_KeyRotation;

typedef struct {
  NIK_Cxn_KeyRotationState state;
  NIK_Handshake handshake;
  NIK_Session new_session;
  bool isinitiator;
  union {
    NIK_Cxn_I_KeyRotation initiator;
    NIK_Cxn_R_KeyRotation responder;
  };
  u64 handshake_sent_time;
} NIK_Cxn_KeyRotation;

typedef enum {
  NIK_Cxn_Event_Invalid,
  NIK_Cxn_Event_Data,
} NIK_Cxn_Event;

typedef struct NIK_Cxn_s NIK_Cxn;
typedef void (*NIK_CxnCb)(NIK_Cxn* cxn, void* userdata, NIK_Cxn_Event e, Bytes data);

struct NIK_Cxn_s {
  NIK_HandshakeKeys keys;

  NIK_CxnCb cb;
  void* userdata;

  NIK_Session current;
  NIK_Session prev;
  NIK_Cxn_KeyRotation key_rotation;
};

void nik_cxn_init(NIK_Cxn *cxn, NIK_HandshakeKeys keys, NIK_CxnCb cb, void* userdata);
void nik_cxn_deinit(NIK_Cxn *cxn);
u64 nik_cxn_get_next_wait_delay(NIK_Cxn* cxn, u64 now);
NIK_Status nik_cxn_incoming(NIK_Cxn* cxn, Bytes msg, u64 now);
NIK_Status nik_cxn_outgoing(NIK_Cxn* cxn, Bytes* msg, u64 now);
