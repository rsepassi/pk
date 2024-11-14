#pragma once

#include "minicoro.h"
#include "stdtypes.h"
#include "uv.h"

typedef struct {
  mco_coro *co;
  bool done;
  void *data;
} co_wait_t;

#define CO_AWAIT(wait)                                                         \
  do {                                                                         \
    while (!(wait)->done)                                                      \
      mco_yield(mco_running());                                                \
  } while (0)

#define CO_DONE(wait)                                                          \
  do {                                                                         \
    (wait)->done = true;                                                       \
    CHECK(mco_resume((wait)->co) == MCO_SUCCESS);                              \
  } while (0)

// Time
void uvco_sleep(uv_loop_t *loop, u64 ms);

// Filesystem
ssize_t uvco_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path);
int uvco_fs_mkdir(uv_loop_t *loop, const char* path, int mode);

// UDP
int uvco_udp_send(uv_loop_t *loop, uv_udp_t *handle, const uv_buf_t bufs[],
                  unsigned int nbufs, const struct sockaddr *addr);
