#pragma once

#include "coco.h"
#include "stdtypes.h"
#include "uv.h"

#define UVCO_DEFAULT_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define UvBuf(b)   uv_buf_init((char*)(b).buf, (unsigned int)(b).len)
#define UvBytes(b) Bytes((b).base, (b).len)

#define UVCHECK(x)                                                             \
  do {                                                                         \
    int __rc = (x);                                                            \
    CHECK(__rc == 0, "%s", uv_strerror(__rc));                                 \
  } while (0)

// Time
void uvco_sleep(uv_loop_t* loop, u64 ms);
int  uvco_await_timeout(uv_loop_t* loop, CocoWait* wait, usize timeout_ms);

// Thread
typedef int (*uvco_trun_fn)(void*);
int uvco_trun(uv_loop_t* loop, uvco_trun_fn work, void* arg);
typedef void (*uvco_arun_fn)(uv_async_t*, void*);
int uvco_arun(uv_loop_t* loop, uvco_arun_fn work, void* arg);

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
  CocoWait               wait;
} UvcoUdpRecv;
int uvco_udp_recv_start(UvcoUdpRecv* recv, uv_udp_t* handle);
int uvco_udp_recv_next(UvcoUdpRecv* recv);
int uvco_udp_recv_next2(UvcoUdpRecv* recv, usize timeout_ms);
