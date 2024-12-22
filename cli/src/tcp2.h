#include "hashmap.h"
#include "ngtcp2/ngtcp2.h"
#include "queue.h"
#include "stdtypes.h"

#define CHECK_TCP2(s)                                                          \
  do {                                                                         \
    int __rc = (int)(s);                                                       \
    CHECK(__rc >= 0, "%s: rc=%d %s", #s, __rc, ngtcp2_strerror(__rc));         \
  } while (0)

typedef struct Tcp2Msg {
  Bytes data;
  i64   stream;  // TCP2_STREAM_*, or from ngtcp2_conn_open_{bidi,uni}_stream
  Node  next;
  usize _offset;
} Tcp2Msg;

typedef struct {
  u8    params_buf[256];
  usize params_len;
  Bytes data;
} Tcp2ZeroRTT;

typedef struct {
  ngtcp2_conn* conn;
  Allocator    allocator;
  ngtcp2_mem   mem;
  Queue        outgoing;
  Hashmap      sent;  // i64 -> Queue
  Tcp2ZeroRTT  zerortt;
} Tcp2Ctx;

typedef struct {
  ngtcp2_recv_stream_data stream;
  ngtcp2_recv_datagram    datagram;
} Tcp2RecvCbs;

int  tcp2_connect(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes* pkt,
                  const Tcp2ZeroRTT* zerortt, Tcp2RecvCbs recv,
                  Allocator allocator, ngtcp2_tstamp now);
int  tcp2_accept(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes pkt, Bytes* resp,
                 Tcp2RecvCbs recv, Allocator allocator, ngtcp2_tstamp now);
void tcp2_conn_deinit(Tcp2Ctx* ctx);

void tcp2_outgoing_enqueue(Tcp2Ctx* ctx, Bytes data, i64 stream);
int  tcp2_outgoing_process(Tcp2Ctx* ctx, Bytes* pkt, ngtcp2_tstamp now,
                           u64 bytes);

// Timers directly from ngtcp2
// ngtcp2_tstamp ngtcp2_conn_get_expiry(ngtcp2_conn *conn)
// int ngtcp2_conn_handle_expiry(ngtcp2_conn *conn, ngtcp2_tstamp ts)

ngtcp2_addr tcp2_ipv4(const char* host, u16 port, ngtcp2_sockaddr_union* addru);
ngtcp2_addr tcp2_ipv6(const char* host, u16 port, ngtcp2_sockaddr_union* addru);
