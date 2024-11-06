// TODO:
// rm CHECKs
// Timer cancellation
// should last_send/recv times be on the Cxn or on the Session?
// zeroing stuff out in the key rotation
// what to do on kr_fail
// TODO: if the message doesn't authenticate, we're still overwriting Handshake
// state
#include "nik_cxn.h"

#include "log.h"
#include "sodium.h"

#define JITTER_SECS 10

#define MS_PER_SEC 1000
#define REKEY_ATTEMPT_MS (NIK_LIMIT_REKEY_ATTEMPT_SECS * MS_PER_SEC)
#define REKEY_TIMEOUT_MS (NIK_LIMIT_REKEY_TIMEOUT_SECS * MS_PER_SEC)
#define KEEPALIVE_MS (NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS * MS_PER_SEC)
#define REJECT_MS (NIK_LIMIT_REJECT_AFTER_SECS * MS_PER_SEC)
#define JITTER_MS (JITTER_SECS * MS_PER_SEC)

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static inline u64 deadline_delay(u64 now, u64 start, u64 timeout) {
  u64 deadline = start + timeout;
  return now > deadline ? 0 : deadline - now;
}

static inline bool deadline_expired(u64 now, u64 start, u64 timeout) {
  return deadline_delay(now, start, timeout) == 0;
}

static inline bool keepalive_required(NIK_Cxn *cxn, u64 now) {
  u64 ka_delay = UINT64_MAX;
  if (cxn->current.recv_n > 0)
    ka_delay = deadline_delay(now, cxn->current.last_send_time, KEEPALIVE_MS);
  return ka_delay == 0;
}

static void kr_init_wait(NIK_Cxn *cxn, u64 now) {
  if (cxn->key_rotation.state != NIK_KR_Null)
    return;

  u64 delay = deadline_delay(now, cxn->key_rotation.handshake_sent_time,
                             REKEY_TIMEOUT_MS);
  u64 jitter = randombytes_uniform(JITTER_MS);
  delay += jitter;

  cxn->key_rotation.isinitiator = true;
  cxn->key_rotation.initiator.handshake_start_time = now + delay;
  cxn->key_rotation.state = NIK_KR_I_StartWait;
}

static void kr_reset(NIK_Cxn *cxn) {
  cxn->key_rotation.state = NIK_KR_Null;
}

static void kr_deliver_data(NIK_Cxn *cxn, u64 now) {
  if (cxn->key_rotation.state != NIK_KR_R_DataWait)
    return;

  cxn->prev = cxn->current;
  cxn->current = cxn->key_rotation.new_session;

  kr_reset(cxn);
}

static void kr_fail(NIK_Cxn *cxn) {
  CHECK(false, "fail? reset?");
  kr_reset(cxn);
}

static void kr_deliver_r2i(NIK_Cxn *cxn, Bytes msg, u64 now) {
  if (cxn->key_rotation.state != NIK_KR_I_R2IWait)
    return;

  if (nik_handshake_respond_check(&cxn->key_rotation.handshake,
                                  (NIK_HandshakeMsg2 *)msg.buf))
    return;

  if (nik_handshake_final(&cxn->key_rotation.handshake,
                          &cxn->key_rotation.new_session, now))
    return;

  cxn->prev = cxn->current;
  cxn->current = cxn->key_rotation.new_session;
}

static void kr_deliver_i2r(NIK_Cxn *cxn, Bytes msg, u64 now) {
  if (cxn->key_rotation.state != NIK_KR_Null)
    return;

  if (msg.len != sizeof(NIK_HandshakeMsg1))
    return;

  if (nik_handshake_init_check(&cxn->key_rotation.handshake, cxn->keys,
                               (NIK_HandshakeMsg1 *)msg.buf))
    return;

  if (nik_handshake_respond(&cxn->key_rotation.handshake,
                            (NIK_HandshakeMsg1 *)msg.buf,
                            &cxn->key_rotation.responder.msg))
    return;

  if (nik_handshake_final(&cxn->key_rotation.handshake,
                          &cxn->key_rotation.new_session, now))
    return;

  cxn->key_rotation.isinitiator = false;
  cxn->key_rotation.state = NIK_KR_R_R2IReady;
}

static void kr_prep_i2r(NIK_Cxn *cxn, u64 now) {
  if (nik_handshake_init(&cxn->key_rotation.handshake, cxn->keys,
                         &cxn->key_rotation.initiator.msg)) {
    kr_fail(cxn);
    return;
  }
  cxn->key_rotation.isinitiator = true;
  cxn->key_rotation.state = NIK_KR_I_I2RReady;
}

static void kr_init(NIK_Cxn *cxn, u64 now) {
  // Advance from {NIK_KR_Null, NIK_KR_I_StartWait} to NIK_KR_I_I2RReady
  if (!(cxn->key_rotation.state == NIK_KR_Null ||
        cxn->key_rotation.state == NIK_KR_I_StartWait))
    return;

  cxn->key_rotation.initiator.handshake_start_time = now;
  kr_prep_i2r(cxn, now);
}

static void kr_expire(NIK_Cxn *cxn, u64 now) {
  // Advance from NIK_KR_I_R2IWait to {NIK_KR_I_I2RReady,NIK_KR_Error}
  if (cxn->key_rotation.state != NIK_KR_I_R2IWait)
    return;

  if (deadline_expired(now, cxn->key_rotation.initiator.handshake_start_time,
                       REJECT_MS * 3))
    kr_fail(cxn);
  else
    kr_prep_i2r(cxn, now);
}

static void advance_time(NIK_Cxn *cxn, u64 now) {
  // Update timers
  switch (cxn->key_rotation.state) {
  // 1. Key rotation initiation delay
  case NIK_KR_I_StartWait:
    if (deadline_expired(now, cxn->key_rotation.initiator.handshake_start_time,
                         0))
      kr_init(cxn, now);
    break;
  // 2. Key rotation retry expiration
  case NIK_KR_I_R2IWait:
    if (deadline_expired(now, cxn->key_rotation.handshake_sent_time,
                         REKEY_TIMEOUT_MS))
      kr_expire(cxn, now);
    break;
  // 3. Keepalive key rotation
  case NIK_KR_Null:
    if ((cxn->current.send_n + cxn->current.recv_n) > 0 &&
        deadline_expired(now, cxn->current.last_recv_time,
                         KEEPALIVE_MS + REKEY_TIMEOUT_MS))
      kr_init_wait(cxn, now);
    break;
  default:
    break;
  }
}

static void handle_datamsg(NIK_Cxn *cxn, Bytes msg, u64 now) {
  if (nik_msg_recv(&cxn->current, &msg, now))
    if (nik_msg_recv(&cxn->prev, &msg, now))
      return;

  if (cxn->key_rotation.state == NIK_KR_R_DataWait)
    kr_deliver_data(cxn, now);

  NIK_Session *session = &cxn->current;
  if (session->isinitiator) {
    if (deadline_expired(now, session->start_time,
                         REJECT_MS - KEEPALIVE_MS - REKEY_TIMEOUT_MS)) {
      DLOG("recv session rekey timer");
      kr_init_wait(cxn, now);
    }
    if ((session->send_n + session->recv_n) >= NIK_LIMIT_REKEY_AFTER_MESSAGES) {
      DLOG("recv session rekey maxmsg");
      return kr_init(cxn, now);
    }
  }

  // TODO: deliver to user cb
}

static NIK_Status kr_i2r_send(NIK_Cxn *cxn, Bytes *msg, u64 now) {
  msg->len = sizeof(NIK_HandshakeMsg1);
  msg->buf = malloc(msg->len);
  memcpy(msg->buf, &cxn->key_rotation.initiator.msg, msg->len);
  cxn->key_rotation.state = NIK_KR_I_R2IWait;
  cxn->key_rotation.handshake_sent_time = now;
  return 0;
}

static NIK_Status kr_r2i_send(NIK_Cxn *cxn, Bytes *msg, u64 now) {
  msg->len = sizeof(NIK_HandshakeMsg2);
  msg->buf = malloc(msg->len);
  memcpy(msg->buf, &cxn->key_rotation.responder.msg, msg->len);
  cxn->key_rotation.state = NIK_KR_R_DataWait;
  return 0;
}

static NIK_Status kr_keepalive_send(NIK_Cxn *cxn, Bytes *msg, u64 now) {
  msg->len = sizeof(NIK_MsgHeader);
  msg->buf = malloc(msg->len);
  return nik_msg_send(&cxn->current, BytesZero, *msg, now);
}

NIK_Status nik_cxn_incoming(NIK_Cxn *cxn, Bytes msg, u64 now) {
  advance_time(cxn, now);

  if (msg.len <= 0)
    return 0;

  NIK_MsgType msgtype = msg.buf[0];
  switch (msgtype) {
  case NIK_Msg_R2I:
    if (cxn->key_rotation.state == NIK_KR_I_R2IWait)
      kr_deliver_r2i(cxn, msg, now);
    break;
  case NIK_Msg_I2R:
    if (cxn->key_rotation.state == NIK_KR_Null)
      kr_deliver_i2r(cxn, msg, now);
    break;
  case NIK_Msg_Data:
    handle_datamsg(cxn, msg, now);
    break;
  default:
    break;
  }

  return 0;
}

NIK_Status nik_cxn_outgoing(NIK_Cxn *cxn, Bytes *msg, u64 now) {
  advance_time(cxn, now);

  // 4 outgoing message types
  // 1. Handshake init
  if (cxn->key_rotation.state == NIK_KR_I_I2RReady) {
    if (!kr_i2r_send(cxn, msg, now))
      return NIK_Status_MsgReady;
  }
  // 2. Handshake response
  if (cxn->key_rotation.state == NIK_KR_R_R2IReady) {
    if (!kr_r2i_send(cxn, msg, now))
      return NIK_Status_MsgReady;
  }
  // 3. Keepalive
  if (keepalive_required(cxn, now)) {
    if (!kr_keepalive_send(cxn, msg, now))
      return NIK_Status_MsgReady;
  }

  // TODO:
  // if (session->isinitiator) {
  //   if (deadline_expired(now, session->start_time,
  //                        NIK_LIMIT_REKEY_AFTER_SECS * MS_PER_SEC)) {
  //     DLOG("send session rekey timer");
  //     return NIK_Status_SessionRekeyTimer;
  //   }

  //   if ((session->send_n + session->recv_n) >=
  //   NIK_LIMIT_REKEY_AFTER_MESSAGES) {
  //     DLOG("send session rekey maxmsg");
  //     return NIK_Status_SessionRekeyMaxmsg;
  //   }
  // }

  // 4. User send
  // TODO

  return 0;
}

u64 nik_cxn_get_next_wait_delay(NIK_Cxn *cxn, u64 now) {
  // If we have a message to send out, the delay is 0
  // 4 outgoing message types
  // 1. Handshake init
  if (cxn->key_rotation.state == NIK_KR_I_I2RReady)
    return 0;
  // 2. Handshake response
  if (cxn->key_rotation.state == NIK_KR_R_R2IReady)
    return 0;
  // 3. Keepalive
  if (keepalive_required(cxn, now))
    return 0;
  // 4. User send
  // TODO

  // If we don't have a message immediately ready, then we have to wake for
  // timers. The maximum allowed delay is the minimum across the timers:
  // 1. Keepalive
  u64 ka_delay = UINT64_MAX;
  if (cxn->current.recv_n > 0)
    ka_delay = deadline_delay(now, cxn->current.last_send_time, KEEPALIVE_MS);
  // 2. Key rotation initiation delay timer
  u64 kr_init_delay = UINT64_MAX;
  if (cxn->key_rotation.state == NIK_KR_I_StartWait)
    kr_init_delay = deadline_delay(
        now, cxn->key_rotation.initiator.handshake_start_time, 0);
  // 3. Key rotation response timeout
  u64 kr_response_delay = UINT64_MAX;
  if (cxn->key_rotation.state == NIK_KR_I_R2IWait)
    kr_response_delay = deadline_delay(
        now, cxn->key_rotation.handshake_sent_time, REKEY_TIMEOUT_MS);

  return MIN(ka_delay, MIN(kr_init_delay, kr_response_delay));
}

void nik_cxn_init(NIK_Cxn *cxn, NIK_HandshakeKeys keys, NIK_CxnCb cb,
                  void *userdata) {
  *cxn = (NIK_Cxn){0};
  cxn->keys = keys;
  cxn->cb = cb;
  cxn->userdata = userdata;
}

void nik_cxn_deinit(NIK_Cxn *cxn) { sodium_memzero(cxn, sizeof(NIK_Cxn)); }
