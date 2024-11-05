#pragma once

#include "stdtypes.h"
#include "uv.h"
#include "minicoro.h"

typedef struct {
  mco_coro *co;
  bool done;
} co_wait_t;

#define CO_AWAIT(wait)                                                         \
  do {                                                                         \
    while (!(wait)->done)                                                      \
      mco_yield(mco_running());                                                \
  } while (0)

#define CO_DONE(wait) do { \
  (wait)->done = true; \
  CHECK(mco_resume((wait)->co) == MCO_SUCCESS); \
} while(0)

void uvco_sleep(uv_loop_t *loop, u64 ms);
ssize_t uvco_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path);
