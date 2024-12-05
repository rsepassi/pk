#include "nik_cxn.h"

#include "log.h"

#define JITTER_MS 334

#define MS_PER_SEC       1000
#define REKEY_AFTER_MS   (NIK_LIMIT_REKEY_AFTER_SECS * MS_PER_SEC)
#define REKEY_ATTEMPT_MS (NIK_LIMIT_REKEY_ATTEMPT_SECS * MS_PER_SEC)
#define REKEY_TIMEOUT_MS (NIK_LIMIT_REKEY_TIMEOUT_SECS * MS_PER_SEC)
#define KEEPALIVE_MS     (NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS * MS_PER_SEC)
#define REJECT_MS        (NIK_LIMIT_REJECT_AFTER_SECS * MS_PER_SEC)

typedef struct {
  u64 keepalive;
  u64 startwait;
  u64 responsewait;
  u64 reconnect;
  u64 expiration;
} TimerDelays;

static inline u64 outgoingq_sz(NIK_Cxn* cxn) {
  return (cxn->outgoing_head < cxn->outgoing_next)
             ? cxn->outgoing_next - cxn->outgoing_head
             : cxn->outgoing_head - cxn->outgoing_next;
}

static inline NIK_Cxn_Status outgoingq_enq(NIK_Cxn* cxn, Bytes payload) {
  if ((outgoingq_sz(cxn) + 1) >= NIK_LIMIT_MAX_OUTGOING)
    return NIK_Cxn_Status_QFull;
  cxn->outgoing[cxn->outgoing_next] = payload;
  cxn->outgoing_next = (cxn->outgoing_next + 1) % NIK_LIMIT_MAX_OUTGOING;
  return 0;
}

static inline Bytes outgoingq_deq(NIK_Cxn* cxn) {
  if (cxn->outgoing_head == cxn->outgoing_next)
    return BytesZero;
  Bytes out                         = cxn->outgoing[cxn->outgoing_head];
  cxn->outgoing[cxn->outgoing_head] = BytesZero;
  cxn->outgoing_head = (cxn->outgoing_head + 1) % NIK_LIMIT_MAX_OUTGOING;
  return out;
}

static inline u64 deadline_delay(u64 now, u64 start, u64 timeout) {
  u64 deadline = start + timeout;
  return now > deadline ? 0 : deadline - now;
}

static inline bool deadline_expired(u64 now, u64 start, u64 timeout) {
  return deadline_delay(now, start, timeout) == 0;
}

static inline bool session_expired(NIK_Cxn* cxn, u64 now) {
  NIK_Session* session = &cxn->current;
  return ((session->send_n + session->recv_n) >=
              NIK_LIMIT_REJECT_AFTER_MESSAGES ||
          deadline_expired(now, cxn->current_start_time, REJECT_MS));
}

static inline u64 keepalive_delay(NIK_Cxn* cxn, u64 now) {
  // If we have received a data message, but have not since sent back a data
  // message nor a keepalive, send a keepalive KEEPALIVE_MS after the last sent
  // data message.
  return (
             // have received a data message
             cxn->last_recv_time > 0 &&
             // haven't sent a data message since the last recv'd msg
             cxn->last_recv_time > cxn->last_send_time &&
             // haven't sent a keepalive since the last recv'd msg
             cxn->last_recv_time > cxn->last_keepalive_send_time)
             // send a keepalive after KEEPALIVE_MS
             ? deadline_delay(now, cxn->last_send_time, KEEPALIVE_MS)
             : UINT64_MAX;
}

#define DELAY_FMT(x) (int)(x)
static inline void debug_log_timers(TimerDelays delays) {
  (void)delays;
  DLOG(
      "TimerDelays(startwait=%d, reconnect=%d, responsewait=%d, "
      "expiration=%d, keepalive=%d)",
      DELAY_FMT(delays.startwait), DELAY_FMT(delays.reconnect),
      DELAY_FMT(delays.responsewait), DELAY_FMT(delays.expiration),
      DELAY_FMT(delays.keepalive));
}

void timer_delays(NIK_Cxn* cxn, u64 now, TimerDelays* delays) {
  // 1. Keepalive
  delays->keepalive = keepalive_delay(cxn, now);
  // 2. Delayed handshake initiation
  delays->startwait =
      (cxn->handshake_state == NIK_CxnHState_I_StartWait)
          ? deadline_delay(now, cxn->handshake.initiator.handshake_start_time,
                           0)
          : UINT64_MAX;
  // 3. Handshake initiation retry
  delays->responsewait =
      (cxn->handshake_state == NIK_CxnHState_I_R2IWait)
          ? deadline_delay(now, cxn->last_handshake_init_time, REKEY_TIMEOUT_MS)
          : UINT64_MAX;
  // 4. Quiet connection reconnect
  delays->reconnect = deadline_delay(
      now,
      MAX(cxn->current_start_time,
          MAX(cxn->last_recv_time, cxn->last_keepalive_recv_time)),
      KEEPALIVE_MS + REKEY_TIMEOUT_MS);
  // 5. max expiration
  delays->expiration =
      deadline_delay(now, cxn->current_start_time, REJECT_MS * 3);

  (void)debug_log_timers;
}

static void handshake_success(NIK_Cxn* cxn, u64 now) {
  DLOG("cxn=%p key rotating", cxn);
  // prev <- current <- next
  cxn->prev               = cxn->current;
  cxn->current            = cxn->next;
  cxn->current_start_time = now;

  // Reset the key rotation state machine to Null.
  cxn->handshake_state = 0;
  sodium_memzero(&cxn->handshake, sizeof(cxn->handshake));
  sodium_memzero(&cxn->next, sizeof(cxn->next));
}

static void handshake_response_arrived(NIK_Cxn* cxn, Bytes msg, u64 now) {
  if (cxn->handshake_state != NIK_CxnHState_I_R2IWait)
    return;
  NIK_Handshake handshake = cxn->handshake.initiator.handshake;
  if (nik_handshake_respond_check(&handshake, (NIK_HandshakeMsg2*)msg.buf))
    return;
  if (nik_handshake_final(&handshake, &cxn->next))
    return;
  handshake_success(cxn, now);
}

static void error(NIK_Cxn* cxn, Bytes err) {
  cxn->cb(cxn, cxn->userdata, NIK_Cxn_Event_Error, err, 0);
}

static void handshake_init(NIK_Cxn* cxn) {
  if (nik_handshake_init(&cxn->handshake.initiator.handshake, cxn->keys,
                         cxn->id, &cxn->handshake.initiator.msg)) {
    error(cxn, Str("bad handshake init"));
    return;
  }

  cxn->handshake_state = NIK_CxnHState_I_I2RReady;
}

static void handshake_init_wait(NIK_Cxn* cxn, u64 now) {
  u64 jitter = randombytes_uniform(JITTER_MS);
  u64 throttle =
      deadline_delay(now, cxn->last_handshake_init_time, REKEY_TIMEOUT_MS);
  cxn->handshake.initiator.handshake_start_time = now + jitter + throttle;
  cxn->handshake_state                          = NIK_CxnHState_I_StartWait;
}

static void handshake_respond_checked(NIK_Cxn* cxn, NIK_Handshake* state,
                                      const NIK_HandshakeMsg1* msg1, u64 now) {
  if (memcmp(msg1->timestamp.timestamp, cxn->max_handshake_timestamp,
             NIK_TIMESTAMP_SZ) < 1)
    return;
  if (nik_handshake_respond(state, cxn->id, msg1,
                            &cxn->handshake.responder.msg)) {
    error(cxn, Str("bad handshake response"));
    return;
  }
  if (nik_handshake_final(state, &cxn->next)) {
    error(cxn, Str("bad handshake response"));
    return;
  }

  cxn->next_start_time = now;
  cxn->handshake_state = NIK_CxnHState_R_R2IReady;
  memcpy(cxn->max_handshake_timestamp, msg1->timestamp.timestamp,
         NIK_TIMESTAMP_SZ);
}

static void handshake_respond(NIK_Cxn* cxn, Bytes msg, u64 now) {
  if (msg.len != sizeof(NIK_HandshakeMsg1))
    return;
  NIK_HandshakeMsg1* msg1 = (NIK_HandshakeMsg1*)msg.buf;
  NIK_Handshake      handshake;
  if (nik_handshake_init_check(&handshake, cxn->keys, msg1))
    return;
  handshake_respond_checked(cxn, &handshake, msg1, now);
}

static void handshake_reset(NIK_Cxn* cxn) {
  cxn->handshake_state = NIK_CxnHState_Null;
}

static void handshake_expire(NIK_Cxn* cxn, u64 now) {
  if (deadline_expired(now, cxn->last_handshake_init_time, REKEY_ATTEMPT_MS))
    handshake_reset(cxn);
  else
    handshake_init(cxn);
}

static void handshake_init_send(NIK_Cxn* cxn, Bytes* msg, u64 now) {
  CHECK(cxn->last_handshake_init_time == 0 ||
            (now >= cxn->last_handshake_init_time + REKEY_TIMEOUT_MS),
        "bug: should never have tried sending this often");
  msg->len = sizeof(NIK_HandshakeMsg1);
  msg->buf = malloc(msg->len);
  memcpy(msg->buf, &cxn->handshake.initiator.msg, msg->len);
  cxn->last_handshake_init_time = now;
  cxn->handshake_state          = NIK_CxnHState_I_R2IWait;
}

static void handshake_response_send(NIK_Cxn* cxn, Bytes* msg) {
  msg->len = sizeof(NIK_HandshakeMsg2);
  msg->buf = malloc(msg->len);
  memcpy(msg->buf, &cxn->handshake.responder.msg, msg->len);
  cxn->handshake_state = NIK_CxnHState_R_DataWait;
}

static NIK_Cxn_Status keepalive_send(NIK_Cxn* cxn, Bytes* msg) {
  msg->len = sizeof(NIK_MsgHeader);
  msg->buf = malloc(msg->len);
  if (nik_msg_send(&cxn->current, BytesZero, *msg)) {
    error(cxn, Str("could not create keepalive"));
    return 1;
  }
  msg->buf[0] = NIK_Msg_Keepalive;
  return 0;
}

static void cxn_init(NIK_Cxn* cxn, NIK_Keys keys, NIK_CxnCb cb,
                     void* userdata) {
  *cxn      = (NIK_Cxn){0};
  cxn->keys = keys;
  randombytes_buf((u8*)&cxn->id, sizeof(cxn->id));
  cxn->cb       = cb;
  cxn->userdata = userdata;
  STATIC_CHECK(NIK_LIMIT_MAX_OUTGOING >= 2);
}

static void cxn_expire(NIK_Cxn* cxn) {
  error(cxn, Str("connection expired"));

  sodium_memzero(&cxn->current, sizeof(cxn->current));
  sodium_memzero(&cxn->prev, sizeof(cxn->prev));
  sodium_memzero(&cxn->next, sizeof(cxn->next));
  cxn->current_start_time = 0;
  cxn->prev_start_time    = 0;
  cxn->next_start_time    = 0;
  cxn->handshake_state    = 0;
  sodium_memzero(&cxn->handshake, sizeof(cxn->handshake));
  cxn->last_send_time           = 0;
  cxn->last_recv_time           = 0;
  cxn->last_keepalive_send_time = 0;
  cxn->last_keepalive_recv_time = 0;
  cxn->last_handshake_init_time = 0;
  sodium_memzero(&cxn->max_handshake_timestamp,
                 sizeof(cxn->max_handshake_timestamp));
}

static void expire_timers(NIK_Cxn* cxn, u64 now) {
  // If time has passed, check if any timers have expired
  if (now <= cxn->maxtime)
    return;
  cxn->maxtime = now;

  TimerDelays delays;
  timer_delays(cxn, now, &delays);

  if (delays.startwait == 0)
    handshake_init(cxn);
  else if (delays.reconnect == 0)
    handshake_init_wait(cxn, now);
  else if (delays.responsewait == 0)
    handshake_expire(cxn, now);

  if (delays.expiration == 0)
    cxn_expire(cxn);

  // note keepalive isn't checked here because the keepalive timer expiring
  // doesn't trigger any state transition.
}

static inline void log_datasend(NIK_Cxn* cxn, u64 now) {
  if (now > cxn->last_send_time)
    cxn->last_send_time = now;
}

static inline void log_datarecv(NIK_Cxn* cxn, u64 now) {
  if (now > cxn->last_recv_time)
    cxn->last_recv_time = now;
}

static inline void log_keepalivesend(NIK_Cxn* cxn, u64 now) {
  if (now > cxn->last_keepalive_send_time)
    cxn->last_keepalive_send_time = now;
}

static inline void log_keepaliverecv(NIK_Cxn* cxn, u64 now) {
  if (now > cxn->last_keepalive_recv_time)
    cxn->last_keepalive_recv_time = now;
}

// Public API
// ============================================================================

void nik_cxn_init(NIK_Cxn* cxn, NIK_Keys keys, NIK_CxnCb cb, void* userdata) {
  cxn_init(cxn, keys, cb, userdata);
  handshake_init(cxn);
}

void nik_cxn_init_responder(NIK_Cxn* cxn, NIK_Keys keys, NIK_Handshake* state,
                            const NIK_HandshakeMsg1* msg1, NIK_CxnCb cb,
                            void* userdata, u64 now) {
  CHECK(now > 0);
  cxn_init(cxn, keys, cb, userdata);
  handshake_respond_checked(cxn, state, msg1, now);
}

void nik_cxn_deinit(NIK_Cxn* cxn) { sodium_memzero(cxn, sizeof(NIK_Cxn)); }

NIK_Cxn_Status nik_cxn_enqueue(NIK_Cxn* cxn, Bytes payload) {
  if (payload.buf == NULL)
    return 1;
  return outgoingq_enq(cxn, payload);
}

u64 nik_cxn_get_next_wait_delay(NIK_Cxn* cxn, u64 now, u64 maxdelay) {
  CHECK(now > 0);

  expire_timers(cxn, now);

  // If an outgoing message is ready, the delay is 0.

  // 1. Handshake init
  if (cxn->handshake_state == NIK_CxnHState_I_I2RReady)
    return 0;
  // 2. Handshake response
  if (cxn->handshake_state == NIK_CxnHState_R_R2IReady)
    return 0;
  // 3. User send
  if (cxn->outgoing[cxn->outgoing_head].buf != NULL)
    return 0;

  // Otherwise, the delay is the minimum of the active timers.
  TimerDelays delays;
  timer_delays(cxn, now, &delays);
  return MIN(maxdelay,                  //
             MIN(delays.keepalive,      //
                 MIN(delays.startwait,  //
                     MIN(delays.responsewait, delays.reconnect))));
}

void nik_cxn_incoming(NIK_Cxn* cxn, Bytes msg, u64 now) {
  if (session_expired(cxn, now))
    error(cxn, Str("session expired"));

  expire_timers(cxn, now);

  if (msg.len <= 0) {
    error(cxn, Str("received empty message"));
    return;
  }

  NIK_MsgType msgtype = msg.buf[0];
  switch (msgtype) {
    case NIK_Msg_R2I:
      handshake_response_arrived(cxn, msg, now);
      return;
    case NIK_Msg_I2R:
      handshake_respond(cxn, msg, now);
      return;
    case NIK_Msg_Data:
    case NIK_Msg_Keepalive:
      break;
    default:
      return;
  }

  // Receive a data or keepalive message

  // Try decoding and validating the message using the sessions next,
  // current, prev in order.
  bool recvd = false;
  do {
    if (cxn->handshake_state == NIK_CxnHState_R_DataWait) {
      if (!nik_msg_recv(&cxn->next, &msg)) {
        handshake_success(cxn, now);
        recvd = true;
        break;
      }
    }

    if (!nik_msg_recv(&cxn->current, &msg)) {
      recvd = true;
      break;
    }

    if (!nik_msg_recv(&cxn->prev, &msg)) {
      recvd = true;
      break;
    }
  } while (0);

  if (!recvd)
    return;

  NIK_Session* session = &cxn->current;
  if (session->isinitiator) {
    if (deadline_expired(now, cxn->current_start_time,
                         REJECT_MS - KEEPALIVE_MS - REKEY_TIMEOUT_MS)) {
      DLOG("recv session rekey timer");
      handshake_init_wait(cxn, now);
    } else if (session->recv_n >= NIK_LIMIT_REKEY_AFTER_MESSAGES) {
      DLOG("recv session rekey maxmsg");
      handshake_init(cxn);
    }
  }

  if (msgtype == NIK_Msg_Data) {
    log_datarecv(cxn, now);
    cxn->cb(cxn, cxn->userdata, NIK_Cxn_Event_Data, msg, now);
  } else {
    log_keepaliverecv(cxn, now);
  }

  return;
}

NIK_Cxn_Status nik_cxn_outgoing(NIK_Cxn* cxn, Bytes* msg, u64 now) {
  if (session_expired(cxn, now)) {
    error(cxn, Str("session expired"));
    return 0;
  }

  expire_timers(cxn, now);

  // Ready outgoing messages

  // 1. Handshake init
  if (cxn->handshake_state == NIK_CxnHState_I_I2RReady) {
    handshake_init_send(cxn, msg, now);
    return NIK_Cxn_Status_MsgReady;
  }
  // 2. Handshake response
  if (cxn->handshake_state == NIK_CxnHState_R_R2IReady) {
    handshake_response_send(cxn, msg);
    return NIK_Cxn_Status_MsgReady;
  }

  // Keepalives and data messages require an active session
  if (cxn->current_start_time == 0)
    return 0;

  // 3. Keepalive
  if (keepalive_delay(cxn, now) == 0) {
    if (!keepalive_send(cxn, msg)) {
      log_keepalivesend(cxn, now);
      return NIK_Cxn_Status_MsgReady;
    } else {
      error(cxn, Str("could not send keepalive"));
    }
  }

  // 4. User send
  Bytes payload = outgoingq_deq(cxn);
  if (!payload.buf)
    return 0;

  msg->len          = nik_sendmsg_sz(payload.len);
  msg->buf          = malloc(msg->len);
  NIK_Status status = nik_msg_send(&cxn->current, payload, *msg);
  if (status != NIK_OK) {
    error(cxn, Str("unable to encrypt payload"));
    goto err;
  }
  log_datasend(cxn, now);

  if (cxn->current.isinitiator) {
    if (deadline_expired(now, cxn->current_start_time, REKEY_AFTER_MS))
      handshake_init_wait(cxn, now);
    else if (cxn->current.send_n >= NIK_LIMIT_REKEY_AFTER_MESSAGES)
      handshake_init(cxn);
  }

  return NIK_Cxn_Status_MsgReady;

err:
  free(msg->buf);
  return 0;
}
