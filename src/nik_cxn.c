// TODO:
// rm CHECKs
// Coro cleanup
// Timer cancellation

#include "nik.h"

#include "log.h"

#include "minicoro.h"
#include "sodium.h"

#define JITTER_SECS 10

#define MS_PER_SEC 1000
#define REKEY_ATTEMPT_MS (NIK_LIMIT_REKEY_ATTEMPT_SECS * MS_PER_SEC)
#define REKEY_TIMEOUT_MS (NIK_LIMIT_REKEY_TIMEOUT_SECS * MS_PER_SEC)
#define KEEPALIVE_MS (NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS * MS_PER_SEC)
#define REJECT_MS (NIK_LIMIT_REJECT_AFTER_SECS * MS_PER_SEC)
#define JITTER_MS (JITTER_SECS * MS_PER_SEC)

typedef struct {
  mco_coro *co;
  bool done;
} co_wait_t;

#define CO_AWAIT(wait)                                                         \
  do {                                                                         \
    while (!(wait)->done)                                                      \
      mco_yield(mco_running());                                                \
  } while (0)

static inline bool deadline_expired(u64 now, u64 start, u64 timeout) {
  return (now >= (start + timeout));
}

static inline u64 sysnow(NIK_Cxn *cxn) {
  u64 now = cxn->sys.now(cxn->sys.userctx);
  CHECK(now < UINT64_MAX);
  return now;
}

static inline void syssend(NIK_Cxn *cxn, Bytes msg) {
  return cxn->sys.send(cxn->sys.userctx, msg);
}

static inline void syssleep(NIK_Cxn *cxn, u64 ms) {
  return cxn->sys.sleep(cxn->sys.userctx, ms);
}

static inline bool is_rekey_active(NIK_Cxn *cxn) {
  return cxn->handshake_initiated_time < UINT64_MAX;
}

static void cxn_fail(NIK_Cxn *cxn) {
  CHECK(false, "cxn fail");
  cxn->failed = true;
  // TODO: zero stuff out
}

static inline bool cxn_active(NIK_Cxn *cxn) {
  if (cxn->cancelled)
    return false;
  if (cxn->failed)
    return false;
  return true;
}

typedef struct {
  u64 now;
  bool jitter;
} RekeyArgs;

static void rekey_coro(mco_coro *co) {
  NIK_Cxn *cxn = (NIK_Cxn *)mco_get_user_data(co);

  RekeyArgs args;
  mco_pop(cxn->rekey_coro, &args, sizeof(args));
  u64 now = args.now;
  bool jitter = args.jitter;

  // Jitter by [0, 10) seconds
  if (jitter) {
    u64 jitter_ms = randombytes_uniform(JITTER_MS);
    DLOG("rekey jitter %dms", (int)jitter_ms);
    syssleep(cxn, jitter_ms);
    now = sysnow(cxn);
  }

  // Never send a handshake more than once every REKEY_TIMEOUT_MS
  if ((now - cxn->last_handshake_sent) < REKEY_TIMEOUT_MS) {
    syssleep(cxn, REKEY_TIMEOUT_MS - (now - cxn->last_handshake_sent));
    now = sysnow(cxn);
  }

  // Set the initial deadline. This may be extended by sends to this peer.
  cxn->rekey_deadline = now + REKEY_ATTEMPT_MS;
  // Set the maximum deadline.
  u64 max_deadline = now + (REJECT_MS * 3);
  while (true) {
    // Fail the connection if we can't reestablish a session within the
    // deadline(s).
    if (now >= cxn->rekey_deadline || now >= max_deadline) {
      DLOG("rekey failed");
      cxn_fail(cxn);
      return;
    }

    // Initiate the handshake.
    NIK_HandshakeMsg1 msg1;
    CHECK0(nik_handshake_init(&cxn->handshake, cxn->keys, &msg1));
    Bytes buf = {sizeof(msg1), (u8 *)&msg1};
    DLOG("sending rekey msg1");
    cxn->last_handshake_sent = now;
    syssend(cxn, buf);
    cxn->handshake_initiated_time = now;

    // Wait REKEY_TIMEOUT_MS for the handshake to finalize
    syssleep(cxn, REKEY_TIMEOUT_MS);
    now = sysnow(cxn);

    // If the handshake finalized, return.
    if (cxn->handshake_initiated_time == UINT64_MAX)
      return;

    // Otherwise, we loop to re-initiate.
  }

  CHECK(false, "unreachable");
}

static void init_rekey(NIK_Cxn *cxn, u64 now, bool jitter) {
  if (is_rekey_active(cxn))
    return;

  mco_desc desc = mco_desc_init(rekey_coro, 0);
  desc.user_data = cxn;

  if (cxn->rekey_coro == NULL) {
    CHECK(mco_create((mco_coro **)&cxn->rekey_coro, &desc) == MCO_SUCCESS);
  } else {
    CHECK(mco_uninit(cxn->rekey_coro) == MCO_SUCCESS);
    CHECK(mco_init(cxn->rekey_coro, &desc) == MCO_SUCCESS);
  }

  cxn->handshake_initiated_time = now;
  RekeyArgs args = {now, jitter};
  mco_push(cxn->rekey_coro, &args, sizeof(args));
  CHECK(mco_resume(cxn->rekey_coro) == MCO_SUCCESS);
}

static void keepalive_coro(mco_coro *co) {
  NIK_Cxn *cxn = (NIK_Cxn *)mco_get_user_data(co);
  NIK_Session *session = &cxn->current;

  while (true) {
    syssleep(cxn, KEEPALIVE_MS);
    u64 now = sysnow(cxn);
    if (!cxn_active(cxn)) return;


    // If we have received a message but haven't sent one in KEEPALIVE_MS, send
    // a keepalive message.
    if (session->recv_n > 0 &&
        deadline_expired(now, session->last_send_time, KEEPALIVE_MS)) {
      DLOG("keepalive");
      Bytes keepalive = {sizeof(NIK_MsgHeader), (u8 *)&cxn->keepalive};
      CHECK0(nik_msg_send(session, (Bytes){0, 0}, keepalive, now));
      syssend(cxn, keepalive);
      if (!cxn_active(cxn)) return;
    }

    // If the session has been active but we haven't received a message in
    // KEEPALIVE_MS + REKEY_TIMEOUT_MS, initiate a rekey.
    if (((session->send_n + session->recv_n) > 0) &&
        deadline_expired(now, session->last_recv_time,
                         KEEPALIVE_MS + REKEY_TIMEOUT_MS)) {
      DLOG("init_rekey ka+rk");
      init_rekey(cxn, now, false);
    }
  }
}

void nik_cxn_init(NIK_Cxn *cxn, NIK_HandshakeKeys keys, NIK_CxnSys sys) {
  *cxn = (NIK_Cxn){0};
  cxn->keys = keys;
  cxn->sys = sys;
  cxn->handshake_initiated_time = UINT64_MAX;

  // Start the keepalive coroutine.
  mco_desc desc = mco_desc_init(keepalive_coro, 0);
  desc.user_data = cxn;
  CHECK(mco_create((mco_coro **)&cxn->keepalive_coro, &desc) == MCO_SUCCESS);
  CHECK(mco_resume(cxn->keepalive_coro) == MCO_SUCCESS);
}

void nik_cxn_deinit(NIK_Cxn *cxn) {
  {
    mco_coro *co = cxn->keepalive_coro;
    if (mco_status(co) != MCO_DEAD) {
      cxn->cancelled = true;
      mco_resume(co);
      LOG("status=%d", mco_status(co));
    }
    CHECK(mco_status(co) == MCO_DEAD);
    CHECK(mco_destroy(co) == MCO_SUCCESS);
  }
  {
    mco_coro *co = cxn->rekey_coro;
    CHECK(mco_status(co) == MCO_DEAD);
    CHECK(mco_destroy(co) == MCO_SUCCESS);
  }

  sodium_memzero(cxn, sizeof(NIK_Cxn));
}

NIK_Status nik_cxn_send(NIK_Cxn *cxn, Bytes payload, Bytes send, u64 now) {
  if (cxn->current.start_time == 0) {
    DLOG("init_rekey send start_time=0");
    init_rekey(cxn, now, false);
    co_wait_t wait = {mco_running(), 0};
    cxn->rekey_waiter = &wait;
    CO_AWAIT(&wait);
  }

  NIK_Status status = nik_msg_send(&cxn->current, payload, send, now);
  DLOG("send status=%d", status);
  switch (status) {
  case NIK_Status_SessionRekeyMaxmsg:
    DLOG("init_rekey send maxmsg");
    init_rekey(cxn, now, false);
  case NIK_Status_SessionRekeyTimer:
    DLOG("init_rekey send timer");
    init_rekey(cxn, now, true);
  case NIK_OK:
    if (is_rekey_active(cxn))
      cxn->rekey_deadline = now + REKEY_ATTEMPT_MS;
    syssend(cxn, send);
    return NIK_OK;
  default:
    return status;
  }
  return 0;
}

static void cxn_rekey_response(NIK_Cxn *cxn, Bytes recv, u64 now) {
  CHECK(is_rekey_active(cxn));
  CHECK(recv.len == sizeof(NIK_HandshakeMsg2));
  CHECK0(nik_handshake_respond_check(&cxn->handshake,
                                     (NIK_HandshakeMsg2 *)recv.buf));
  DLOG("initiator finalizing");
  cxn->prev = cxn->current;
  CHECK0(nik_handshake_final(&cxn->handshake, &cxn->current, now));
  cxn->handshake_initiated_time = UINT64_MAX;
  if (cxn->rekey_waiter) {
    DLOG("rekey resume waiter");
    co_wait_t *wait = (co_wait_t *)cxn->rekey_waiter;
    cxn->rekey_waiter = 0;
    wait->done = true;
    CHECK(mco_resume(wait->co) == MCO_SUCCESS);
  }
}

static void cxn_rekey_responder(NIK_Cxn *cxn, Bytes recv, u64 now) {
  CHECK(!is_rekey_active(cxn));

  CHECK(recv.len == sizeof(NIK_HandshakeMsg1));
  CHECK0(nik_handshake_init_check(&cxn->handshake, cxn->keys,
                                  (NIK_HandshakeMsg1 *)recv.buf));

  NIK_HandshakeMsg2 msg2;
  CHECK0(nik_handshake_respond(&cxn->handshake, (NIK_HandshakeMsg1 *)recv.buf,
                               &msg2));
  Bytes buf = {sizeof(NIK_HandshakeMsg2), (u8 *)&msg2};
  cxn->prev = cxn->current;
  DLOG("responder finalizing");
  CHECK0(nik_handshake_final(&cxn->handshake, &cxn->current, now));
  syssend(cxn, buf);
}

NIK_Status nik_cxn_recv(NIK_Cxn *cxn, Bytes *recv, u64 now) {
  if (recv->len > 0) {
    switch (recv->buf[0]) {
    case NIK_Msg_I2R:
      DLOG("recv I2R");
      cxn_rekey_responder(cxn, *recv, now);
      return NIK_Status_InternalMsg;
    case NIK_Msg_R2I:
      DLOG("recv R2I");
      cxn_rekey_response(cxn, *recv, now);
      return NIK_Status_InternalMsg;
    case NIK_Msg_Data:
      DLOG("recv data");
      break;
    default:
      return NIK_Error;
    }
  }

  // Data message
  NIK_Status status = nik_msg_recv(&cxn->current, recv, now);
  switch (status) {
  case NIK_Status_SessionRekeyMaxmsg:
    DLOG("init_rekey recv maxmsg");
    init_rekey(cxn, now, false);
    return NIK_OK;
  case NIK_Status_SessionRekeyTimer:
    DLOG("init_rekey recv timer");
    init_rekey(cxn, now, true);
    return NIK_OK;
  default:
    return status;
  }
  return 0;
}
