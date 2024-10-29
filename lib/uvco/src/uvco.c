#include "uvco.h"

#include <stdbool.h>

#include "log.h"
#include "minicoro.h"

typedef struct {
  mco_coro *co;
  bool done;
} co_wait_t;

static void fs_cb(uv_fs_t* req) {
  co_wait_t* wait = (co_wait_t*)req->data;
  wait->done = true;
  CHECK(mco_resume(wait->co) == MCO_SUCCESS);
}

ssize_t uvco_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path) {
  co_wait_t wait = {mco_running(), 0};
  req->data = &wait;
  ssize_t rc = uv_fs_stat(loop, req, path, fs_cb);
  if (rc != 0) return rc;
  while (!wait.done) mco_yield(mco_running());
  return req->result;
}
