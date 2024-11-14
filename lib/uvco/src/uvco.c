#include "uvco.h"

#include <stdbool.h>

#include "log.h"

static void fs_cb(uv_fs_t *req) { CO_DONE((co_wait_t *)req->data); }

static void timer_cb(uv_timer_t *handle) { CO_DONE((co_wait_t *)handle->data); }

static void udp_send_cb(uv_udp_send_t *req, int status) {
  co_wait_t *wait = (co_wait_t *)req->data;
  wait->data = &status;
  CO_DONE(wait);
}

ssize_t uvco_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path) {
  co_wait_t wait = {mco_running(), 0};
  req->data = &wait;
  ssize_t rc = uv_fs_stat(loop, req, path, fs_cb);
  if (rc != 0)
    return rc;
  CO_AWAIT(&wait);
  return req->result;
}

int uvco_fs_mkdir(uv_loop_t *loop, const char* path, int mode) {
  co_wait_t wait = {mco_running(), 0};
  uv_fs_t req;
  req.data = &wait;
  if (uv_fs_mkdir(loop, &req, path, mode, fs_cb) != 0)
    return 1;
  CO_AWAIT(&wait);
  return req.result;
}

void uvco_sleep(uv_loop_t *loop, u64 ms) {
  co_wait_t wait = {mco_running(), 0};
  uv_timer_t timer;
  uv_timer_init(loop, &timer);
  timer.data = &wait;
  int rc = uv_timer_start(&timer, timer_cb, ms, 0);
  CHECK0(rc);
  CO_AWAIT(&wait);
}

int uvco_udp_send(uv_loop_t *loop, uv_udp_t *handle, const uv_buf_t bufs[],
                  unsigned int nbufs, const struct sockaddr *addr) {
  co_wait_t wait = {mco_running(), 0};
  uv_udp_send_t req;
  req.data = &wait;
  CHECK0(uv_udp_send(&req, handle, bufs, nbufs, addr, udp_send_cb));
  CO_AWAIT(&wait);
  int status = *(int *)wait.data;
  return status;
}
