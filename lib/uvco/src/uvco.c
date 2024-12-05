#include "uvco.h"

#include "log.h"

#include <stdbool.h>

#define UV_BUFLEN_T __typeof__(((uv_buf_t*)0)->len)

static void fs_cb(uv_fs_t* req) {
  co_wait_t* wait = req->data;
  CO_DONE(wait);
}

static void del_handle_cb(uv_handle_t* req) { free(req); }

static void timer_cb(uv_timer_t* handle) { CO_DONE((co_wait_t*)handle->data); }

static void udp_send_cb(uv_udp_send_t* req, int status) {
  co_wait_t* wait = (co_wait_t*)req->data;
  wait->data = &status;
  CO_DONE(wait);
}

ssize_t uvco_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path) {
  co_wait_t wait = {mco_running(), 0, 0};
  req->data = &wait;
  ssize_t rc = uv_fs_stat(loop, req, path, fs_cb);
  if (rc != 0)
    return rc;
  CO_AWAIT(&wait);
  return req->result;
}

int uvco_fs_mkdir(uv_loop_t* loop, const char* path, int mode) {
  co_wait_t wait = {mco_running(), 0, 0};
  uv_fs_t req;
  req.data = &wait;
  if (uv_fs_mkdir(loop, &req, path, mode, fs_cb) != 0)
    return 1;
  CO_AWAIT(&wait);
  uv_fs_req_cleanup(&req);
  return (int)req.result;
}

void uvco_sleep(uv_loop_t* loop, u64 ms) {
  co_wait_t wait = {mco_running(), 0, 0};
  uv_timer_t* timer = malloc(sizeof(uv_timer_t));
  uv_timer_init(loop, timer);
  timer->data = &wait;
  int rc = uv_timer_start(timer, timer_cb, ms, 0);
  CHECK0(rc);
  CO_AWAIT(&wait);
  uv_close((uv_handle_t*)timer, del_handle_cb);
}

int uvco_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs,
                  const struct sockaddr* addr) {
  co_wait_t wait = {mco_running(), 0, 0};
  uv_udp_send_t req;
  req.data = &wait;
  CHECK0(uv_udp_send(&req, handle, bufs, nbufs, addr, udp_send_cb));
  CO_AWAIT(&wait);
  int status = *(int*)wait.data;
  return status;
}

int uvco_fs_open(uv_loop_t* loop, const char* path, int flags, int mode,
                 uv_file* fd) {
  int rc = 1;
  co_wait_t wait = {mco_running(), 0, 0};
  uv_fs_t* req = malloc(sizeof(uv_fs_t));
  req->data = &wait;
  if (uv_fs_open(loop, req, path, flags, mode, fs_cb))
    goto end;
  CO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  *fd = (uv_file)req->result;
  rc = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

int uvco_fs_write(uv_loop_t* loop, uv_file fd, Bytes contents, usize offset,
                  usize* nwritten) {
  int rc = 1;
  co_wait_t wait = {mco_running(), 0, 0};
  uv_fs_t* req = malloc(sizeof(uv_fs_t));
  req->data = &wait;
  uv_buf_t buf = uv_buf_init((char*)contents.buf, (u32)contents.len);
  if (uv_fs_write(loop, req, fd, &buf, 1, offset, fs_cb))
    goto end;
  CO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  *nwritten = req->result;
  rc = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

void uvco_fs_close(uv_loop_t* loop, uv_file fd) {
  co_wait_t wait = {mco_running(), 0, 0};
  uv_fs_t* req = malloc(sizeof(uv_fs_t));
  req->data = &wait;
  if (uv_fs_close(loop, req, fd, fs_cb))
    goto end;
  CO_AWAIT(&wait);
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
  int rc = 1;
  co_wait_t wait = {mco_running(), 0, 0};
  uv_fs_t* req = malloc(sizeof(uv_fs_t));
  req->data = &wait;
  uv_buf_t buf = uv_buf_init((char*)contents->buf, (u32)contents->len);
  if (uv_fs_read(loop, req, fd, &buf, 1, offset, fs_cb))
    goto end;
  CO_AWAIT(&wait);
  if (req->result < 0)
    goto end;
  contents->len = req->result;
  rc = 0;
end:
  uv_fs_req_cleanup(req);
  free(req);
  return rc;
}

#define UDP_MAXSZ 1600

static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size,
                         uv_buf_t* buf) {
  (void)handle;
  (void)suggested_size;
  static u8 static_buf[UDP_MAXSZ] = {0};
  *buf = uv_buf_init((void*)static_buf, UDP_MAXSZ);
}

static void udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr, unsigned flags) {
  (void)flags;

  UvcoUdpRecv* ctx = handle->data;

  // End of message, nothing needs to be done
  if (nread == 0 && addr == NULL)
    return;

  // nobody's waiting...
  if (ctx->wait.co == NULL) {
    LOG("message dropped, no waiter");
    return;
  }

  ctx->nread = nread;
  ctx->addr = addr;
  ctx->buf = *buf;
  ctx->buf.len = nread >= 0 ? (UV_BUFLEN_T)nread : 0;

  if (ctx->buf.len > UDP_MAXSZ)
    ctx->nread = UV_EOVERFLOW;

  CO_DONE(&ctx->wait);
}

int uvco_udp_recv_start(UvcoUdpRecv* recv, uv_udp_t* handle) {
  *recv = (UvcoUdpRecv){0};
  recv->udp = handle;
  recv->udp->data = recv;
  return uv_udp_recv_start(recv->udp, udp_alloc_cb, udp_recv_cb);
}

ssize_t uvco_udp_recv_next(UvcoUdpRecv* recv) {
  recv->udp->data = recv;
  recv->wait = (co_wait_t){0};
  recv->wait.co = mco_running();

  CO_AWAIT(&recv->wait);

  recv->wait = (co_wait_t){0};
  return recv->nread;
}
