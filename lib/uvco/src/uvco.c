#include "uvco.h"

#include "log.h"
#include "stdnet.h"
#include "stdtime.h"

#include <stdbool.h>

#define UV_BUFLEN_T __typeof__(((uv_buf_t*)0)->len)
#define UDP_MAXSZ   1600

static void fs_cb(uv_fs_t* req) {
  CocoWait* wait = req->data;
  COCO_DONE(wait);
}

static void timer_cb(uv_timer_t* handle) { COCO_DONE((CocoWait*)handle->data); }

ssize_t uvco_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path) {
  CocoWait wait = CocoWait();
  req->data     = &wait;
  ssize_t rc    = uv_fs_stat(loop, req, path, fs_cb);
  if (rc != 0)
    return rc;
  COCO_AWAIT(&wait);
  return req->result;
}

int uvco_fs_mkdir(uv_loop_t* loop, const char* path, int mode) {
  CocoWait wait = CocoWait();
  uv_fs_t  req;
  req.data = &wait;
  if (uv_fs_mkdir(loop, &req, path, mode, fs_cb) != 0)
    return 1;
  COCO_AWAIT(&wait);
  uv_fs_req_cleanup(&req);
  return (int)req.result;
}

typedef struct {
  CocoWait wait;
  int      status;
} Send;

static void udp_send_cb(uv_udp_send_t* req, int status) {
  Send* send   = req->data;
  send->status = status;
  COCO_DONE(&send->wait);
}

int uvco_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs,
                  const struct sockaddr* addr) {
  Send send    = {0};
  send.wait.co = mco_running();
  uv_udp_send_t req;
  req.data = &send;
  int rc;
  if ((rc = uv_udp_send(&req, handle, bufs, nbufs, addr, udp_send_cb)))
    return rc;
  COCO_AWAIT(&send.wait);
  return send.status;
}

int uvco_fs_open(uv_loop_t* loop, const char* path, int flags, int mode,
                 uv_file* fd) {
  int      rc   = 1;
  CocoWait wait = CocoWait();
  uv_fs_t* req  = malloc(sizeof(uv_fs_t));
  req->data     = &wait;
  if (uv_fs_open(loop, req, path, flags, mode, fs_cb))
    goto end;
  COCO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  *fd = (uv_file)req->result;
  rc  = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

int uvco_fs_write(uv_loop_t* loop, uv_file fd, Bytes contents, usize offset,
                  usize* nwritten) {
  int      rc   = 1;
  CocoWait wait = CocoWait();
  uv_fs_t* req  = malloc(sizeof(uv_fs_t));
  req->data     = &wait;
  uv_buf_t buf  = uv_buf_init((char*)contents.buf, (u32)contents.len);
  if (uv_fs_write(loop, req, fd, &buf, 1, offset, fs_cb))
    goto end;
  COCO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  *nwritten = req->result;
  rc        = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

void uvco_fs_close(uv_loop_t* loop, uv_file fd) {
  CocoWait wait = CocoWait();
  uv_fs_t* req  = malloc(sizeof(uv_fs_t));
  req->data     = &wait;
  if (uv_fs_close(loop, req, fd, fs_cb))
    goto end;
  COCO_AWAIT(&wait);
end:
  uv_fs_req_cleanup(req);
  free(req);
}

int uvco_fs_writefull(uv_loop_t* loop, const char* path, Bytes contents) {
  uv_file fd;
  if (uvco_fs_open(loop, path, UV_FS_O_WRONLY | UV_FS_O_CREAT | UV_FS_O_TRUNC,
                   UVCO_DEFAULT_FILE_MODE, &fd))
    return 1;
  usize nwritten;
  if (uvco_fs_write(loop, fd, contents, 0, &nwritten))
    return 1;
  if (nwritten != contents.len)
    return 1;
  uvco_fs_close(loop, fd);
  return 0;
}

int uvco_fs_read(uv_loop_t* loop, uv_file fd, Bytes* contents, usize offset) {
  int      rc   = 1;
  CocoWait wait = CocoWait();
  uv_fs_t* req  = malloc(sizeof(uv_fs_t));
  req->data     = &wait;
  uv_buf_t buf  = uv_buf_init((char*)contents->buf, (u32)contents->len);
  if (uv_fs_read(loop, req, fd, &buf, 1, offset, fs_cb))
    goto end;
  COCO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  contents->len = req->result;
  rc            = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

// Ensure that the UDP buffer is suitably aligned
typedef union {
  u8          buf[UDP_MAXSZ];
  max_align_t _;
} UdpBuf;

static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size,
                         uv_buf_t* buf) {
  (void)handle;
  (void)suggested_size;
  static UdpBuf static_buf = {0};

  *buf = uv_buf_init((void*)static_buf.buf, UDP_MAXSZ);
}

static void udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr, unsigned flags) {
  (void)flags;

  // End of message, nothing needs to be done
  if (nread == 0 && addr == NULL)
    return;

  UvcoUdpRecv* ctx = handle->data;

  // nobody's waiting...
  if (ctx == NULL || ctx->wait.co == NULL) {
    DLOG("message dropped, no waiter");
    return;
  }

  ctx->nread   = nread;
  ctx->addr    = addr;
  ctx->buf     = *buf;
  ctx->buf.len = nread >= 0 ? (UV_BUFLEN_T)nread : 0;

  if (ctx->buf.len > UDP_MAXSZ)
    ctx->nread = UV_EOVERFLOW;

  COCO_DONE(&ctx->wait);
}

int uvco_udp_recv_start(UvcoUdpRecv* recv, uv_udp_t* handle) {
  *recv           = (UvcoUdpRecv){0};
  recv->udp       = handle;
  recv->udp->data = recv;
  return uv_udp_recv_start(recv->udp, udp_alloc_cb, udp_recv_cb);
}

int uvco_udp_recv_next(UvcoUdpRecv* recv) {
  recv->udp->data = recv;
  recv->wait      = (CocoWait){0};
  recv->wait.co   = mco_running();

  COCO_AWAIT(&recv->wait);

  recv->udp->data = 0;
  recv->wait      = (CocoWait){0};

  if (recv->nread < 0)
    return (int)recv->nread;

  return 0;
}

typedef struct {
  uv_timer_t timer;
  CocoWait   wait;
} UvcoTimer;

int uvco_timer_start(UvcoTimer* t, uv_loop_t* loop, usize ms) {
  ZERO(t);
  t->wait = CocoWait();
  uv_timer_init(loop, &t->timer);
  t->timer.data = &t->wait;
  UVCHECK(uv_timer_start(&t->timer, timer_cb, ms, 0));
  return 0;
}

void uvco_sleep(uv_loop_t* loop, u64 ms) {
  CocoWait wait = CocoWait();
  CHECK(uvco_await_timeout(loop, &wait, ms) == UV_ETIMEDOUT);
}

static void handle_free(uv_handle_t* h) { free(h->data); }

int uvco_await_timeout(uv_loop_t* loop, CocoWait* wait, usize timeout_ms) {
  // Start timer
  UvcoTimer* ts = malloc(sizeof(UvcoTimer));
  UvcoTimer* t  = ts;
  UVCHECK(uvco_timer_start(t, loop, timeout_ms));

  // Suspend
  while (!t->wait.done && !wait->done)
    coco_yield();

  // We're back
  int rc = 0;
  if (t->wait.done) {
    // Timer expired
    rc = UV_ETIMEDOUT;
  } else {
    // Cancel the timer
    UVCHECK(uv_timer_stop(&t->timer));
  }

  // Cleanup
  t->timer.data = t;
  uv_close((uv_handle_t*)&t->timer, handle_free);

  return rc;
}

int uvco_udp_recv_next2(UvcoUdpRecv* recv, usize timeout_ms) {
  // Register as waiting on the udp socket
  recv->udp->data = recv;
  recv->wait      = CocoWait();

  int rc = uvco_await_timeout(recv->udp->loop, &recv->wait, timeout_ms);
  if (rc == 0) {
    // Message arrived
    if (recv->nread < 0)
      rc = (int)recv->nread;
  }

  // Cleanup
  recv->udp->data = 0;

  return rc;
}

typedef struct {
  CocoWait     wait;
  int          uv_status;
  int          fn_status;
  uvco_trun_fn work;
  void*        arg;
} TRun;

static void trun_after_work(uv_work_t* req, int status) {
  TRun* trun      = req->data;
  trun->uv_status = status;
  COCO_DONE(&trun->wait);
}

static void trun_work(uv_work_t* req) {
  TRun* trun      = req->data;
  trun->fn_status = trun->work(trun->arg);
}

int uvco_trun(uv_loop_t* loop, uvco_trun_fn work, void* arg) {
  TRun trun    = {0};
  trun.work    = work;
  trun.arg     = arg;
  trun.wait.co = mco_running();

  uv_work_t req;
  req.data = &trun;
  int rc;
  if ((rc = uv_queue_work(loop, &req, trun_work, trun_after_work)))
    return rc;

  COCO_AWAIT(&trun.wait);

  if (trun.uv_status != 0)
    return trun.uv_status;

  return trun.fn_status;
}

static void uvco_async_cb(uv_async_t* async) {
  CocoWait* wait = async->data;
  COCO_DONE(wait);
}

int uvco_arun(uv_loop_t* loop, uvco_arun_fn work, void* arg) {
  uv_async_t* async = malloc(sizeof(uv_async_t));
  CocoWait    wait  = CocoWait();
  async->data       = &wait;
  int rc;
  if ((rc = uv_async_init(loop, async, uvco_async_cb)))
    goto cleanup;
  work(async, arg);
  COCO_AWAIT(&wait);

  rc = 0;

cleanup:
  async->data = async;
  uv_close((uv_handle_t*)async, handle_free);

  return rc;
}
