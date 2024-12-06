#pragma once

#include "minicoro.h"
#include "stdtypes.h"
#include "uv.h"

typedef struct {
  mco_coro* co;
  bool      done;
  void*     data;
} co_wait_t;

#define UVCO_DEFAULT_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define CO_AWAIT(wait)                                                         \
  do {                                                                         \
    while (!(wait)->done) {                                                    \
      CHECK0(mco_yield(mco_running()));                                        \
    }                                                                          \
  } while (0)

#define CO_DONE(wait)                                                          \
  do {                                                                         \
    (wait)->done = true;                                                       \
    CHECK(mco_resume((wait)->co) == MCO_SUCCESS);                              \
  } while (0)

#define UvBuf(b) uv_buf_init((char*)(b).buf, (unsigned int)(b).len)

// Time
void uvco_sleep(uv_loop_t* loop, u64 ms);

// Filesystem
ssize_t uvco_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path);
int     uvco_fs_mkdir(uv_loop_t* loop, const char* path, int mode);
int     uvco_fs_open(uv_loop_t* loop, const char* path, int flags, int mode,
                     uv_file* fd);
int     uvco_fs_write(uv_loop_t* loop, uv_file fd, Bytes contents, usize offset,
                      usize* nwritten);
int  uvco_fs_read(uv_loop_t* loop, uv_file fd, Bytes* contents, usize offset);
void uvco_fs_close(uv_loop_t* loop, uv_file fd);
int  uvco_fs_writefull(uv_loop_t* loop, const char* path, Bytes contents);

// UDP send
int uvco_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs,
                  const struct sockaddr* addr);

// UDP recv
typedef struct {
  uv_udp_t*              udp;
  uv_buf_t               buf;
  const struct sockaddr* addr;
  ssize_t                nread;
  co_wait_t              wait;
} UvcoUdpRecv;
int     uvco_udp_recv_start(UvcoUdpRecv* recv, uv_udp_t* handle);
ssize_t uvco_udp_recv_next(UvcoUdpRecv* recv);
