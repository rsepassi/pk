#include "tcp2.h"

#include "allocatormi.h"
#include "sodium.h"
#include "stdnet.h"
#include "stdtime.h"

static int tcp2_recv_datagram(ngtcp2_conn* conn, uint32_t flags,
                              const uint8_t* data, size_t datalen,
                              void* user_data) {
  LOG("");
  // NGTCP2_DATAGRAM_FLAG_0RTT

  Tcp2Ctx* ctx = user_data;
  (void)ctx;

  return 0;
}

int tcp2_recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                          uint64_t offset, const uint8_t* data, size_t datalen,
                          void* user_data, void* stream_user_data) {
  bool stream_end = flags & NGTCP2_STREAM_DATA_FLAG_FIN;
  bool zerortt    = flags & NGTCP2_STREAM_DATA_FLAG_0RTT;

  Tcp2Ctx* ctx = user_data;

  LOG("FIN=%d 0RTT=%d", stream_end, zerortt);
  LOG("DATA: %.*s", (int)datalen, data);

  if (ngtcp2_conn_is_server(conn))
    tcp2_outgoing_enqueue(ctx, Str("hi from server"), stream_id);

  return 0;
}

int demo_tcp2(int argc, char** argv) {
  LOG("");

  // ngtcp2_conn_get_send_quantum
  // ngtcp2_conn_get_expiry
  // NGTCP2_ERR_VERSION_NEGOTIATION, ngtcp2_pkt_write_version_negotiation
  // NGTCP2_ERR_IDLE_CLOSE, drop connection without calling write

  Tcp2RecvCbs recv_cbs = {
      .stream   = tcp2_recv_stream_data,
      .datagram = tcp2_recv_datagram,
  };

  ngtcp2_sockaddr_union client_addru;
  ngtcp2_addr           client_addr =
      tcp2_ipv4(STDNET_IPV4_LOCALHOST, 2222, &client_addru);

  ngtcp2_sockaddr_union server_addru;
  ngtcp2_addr           server_addr =
      tcp2_ipv6(STDNET_IPV6_LOCALHOST, 3333, &server_addru);

  Allocator alloc = allocatormi_allocator();

  u64 now = stdtime_now_monotonic_ns();

  // Client connect
  Bytes       pkt_connect;
  ngtcp2_path client_path = {.local = client_addr, .remote = server_addr};
  Tcp2Ctx     client_ctx;
  CHECK_TCP2(tcp2_connect(&client_ctx, &client_path, &pkt_connect, 0, recv_cbs,
                          alloc, now));

  // Server reply
  now                    = stdtime_now_monotonic_ns();
  Tcp2Ctx     server_ctx = {0};
  Bytes       pkt_connect_reply;
  ngtcp2_path server_path = {.local = server_addr, .remote = client_addr};
  LOG("receiving packet");
  CHECK_TCP2(tcp2_accept(&server_ctx, &server_path, pkt_connect,
                         &pkt_connect_reply, recv_cbs, alloc, now));
  allocator_free(client_ctx.allocator, pkt_connect);

  // Client finish and send data
  now = stdtime_now_monotonic_ns();
  Bytes msg;
  CHECK0(allocator_u8(client_ctx.allocator, &msg, NGTCP2_MAX_UDP_PAYLOAD_SIZE));
  LOG("client receiving packet");
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0,
                                  pkt_connect_reply.buf, pkt_connect_reply.len,
                                  now));

  LOG("client send some data");
  i64 stream;
  {
    CHECK_TCP2(
        ngtcp2_conn_open_bidi_stream(client_ctx.conn, &stream, &client_ctx));
    tcp2_outgoing_enqueue(&client_ctx, Str("hi from client"), stream);
    CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg, now, 0));
  }
  allocator_free(server_ctx.allocator, pkt_connect_reply);

  // Server data receive
  now = stdtime_now_monotonic_ns();
  Bytes msg2;
  CHECK0(
      allocator_u8(client_ctx.allocator, &msg2, NGTCP2_MAX_UDP_PAYLOAD_SIZE));
  LOG("server receiving msg");
  CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path, 0, msg.buf,
                                  msg.len, now));
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
  allocator_free(client_ctx.allocator, msg);

  LOG("client receiving packet");
  now = stdtime_now_monotonic_ns();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0, msg2.buf,
                                  msg2.len, now));

  // Let's try a connection migration
  now = stdtime_now_monotonic_ns();
  ngtcp2_sockaddr_union client_addru_new;
  ngtcp2_addr           client_addr_new =
      tcp2_ipv4(STDNET_IPV4_LOCALHOST, 2223, &client_addru_new);
  ngtcp2_path client_path_new = {.local  = client_addr_new,
                                 .remote = server_addr};
  ngtcp2_path server_path_new = {.local  = server_addr,
                                 .remote = client_addr_new};
  CHECK_TCP2(
      ngtcp2_conn_initiate_migration(client_ctx.conn, &client_path_new, now));
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));

  for (int i = 0; i < 5; ++i) {
    if (msg2.len) {
      // Server recv
      now = stdtime_now_monotonic_ns();
      CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0,
                                      msg2.buf, msg2.len, now));
      msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
    } else
      LOG("skip");

    if (msg2.len) {
      // Client recv
      now = stdtime_now_monotonic_ns();
      CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path_new, 0,
                                      msg2.buf, msg2.len, now));
      msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));
    } else
      LOG("skip");
  }

  now = stdtime_now_monotonic_ns();
  tcp2_outgoing_enqueue(&client_ctx, Str("hi2 from client"), stream);
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));

  now = stdtime_now_monotonic_ns();
  CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0,
                                  msg2.buf, msg2.len, now));
  now      = stdtime_now_monotonic_ns();
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));

  now = stdtime_now_monotonic_ns();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path_new, 0,
                                  msg2.buf, msg2.len, now));

  // Copy out 0-RTT params
  Tcp2ZeroRTT zerortt = client_ctx.zerortt;

  // Close the connection
  now                = stdtime_now_monotonic_ns();
  msg2.len           = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  ngtcp2_ccerr ccerr = {0};
  ccerr.type         = NGTCP2_CCERR_TYPE_APPLICATION;
  ngtcp2_ssize sz    = ngtcp2_conn_write_connection_close(
      client_ctx.conn, &client_path_new, 0, msg2.buf, msg2.len, &ccerr, now);
  CHECK_TCP2(sz);
  msg2.len = sz;

  now = stdtime_now_monotonic_ns();
  CHECK(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0, msg2.buf,
                             msg2.len, now) == NGTCP2_ERR_DRAINING);

  // Cleanup

  allocator_free(client_ctx.allocator, msg2);

  tcp2_conn_deinit(&client_ctx);
  tcp2_conn_deinit(&server_ctx);

  // Attempt a 0-RTT data send
  LOG("0rtt send");
  now          = stdtime_now_monotonic_ns();
  zerortt.data = Str("zero!");
  CHECK_TCP2(tcp2_connect(&client_ctx, &client_path, &pkt_connect, &zerortt,
                          recv_cbs, alloc, now));
  LOG("0rtt recv");
  now = stdtime_now_monotonic_ns();
  CHECK_TCP2(tcp2_accept(&server_ctx, &server_path, pkt_connect,
                         &pkt_connect_reply, recv_cbs, alloc, now));
  LOG("0rtt reply");
  now = stdtime_now_monotonic_ns();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0,
                                  pkt_connect_reply.buf, pkt_connect_reply.len,
                                  now));

  allocator_free(client_ctx.allocator, pkt_connect);
  allocator_free(server_ctx.allocator, pkt_connect_reply);

  tcp2_conn_deinit(&client_ctx);
  tcp2_conn_deinit(&server_ctx);

  return 0;
}
