#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "uv.h"
#include "picoquic.h"
#include "picoquic_utils.h"

#define UV_CHECK(x) do { \
    int rc = (int)(x); \
    CHECK(rc >= 0, "uv error: %s", uv_strerror(rc)); \
  } while (0)

#define PQ_CHECK(x) do { \
    int rc = (x); \
    CHECK(rc == 0, "picoquic error %d", rc); \
  } while (0)

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 4443
#define MAX_SEND_PACKET_SIZE PICOQUIC_MAX_PACKET_SIZE
#define SERVER_CERT "cert.pem"
#define SERVER_KEY "key.pem"


typedef struct {
    picoquic_quic_t* quic;
    picoquic_cnx_t* qclient;
    uv_loop_t* loop;
    uv_udp_t socket;
    uv_timer_t timer;
    bool quic_wakeup;
    struct sockaddr_storage myaddr;
    bool shutdown;
} client_ctx_t;

typedef struct {
  bool sent;
} client_stream_ctx_t;

typedef struct {
  uv_udp_send_t req;
  uv_buf_t bufuv;
  uint8_t buf[MAX_SEND_PACKET_SIZE];
} send_state_t;

static void on_uv_send(uv_udp_send_t *req, int status) {
  if (status < 0) {
    LOG("uv send fail: %s", uv_strerror(status));
  }

  send_state_t* state = (send_state_t*)req->data;
  free(state);
}

static bool quic_send(client_ctx_t* ctx) {
  send_state_t* state = (send_state_t*)malloc(sizeof(send_state_t));
  state->bufuv.base = (char*)state->buf;

  struct sockaddr_storage addr_local;
  struct sockaddr_storage addr_peer;
  int if_index = 0;
  picoquic_connection_id_t logcid;
  picoquic_cnx_t* last_cnx;
  int send_rc = picoquic_prepare_next_packet(
        ctx->quic,
        picoquic_get_quic_time(ctx->quic),
        state->buf,
        MAX_SEND_PACKET_SIZE,
        &state->bufuv.len,
        &addr_peer,
        &addr_local,
        &if_index,
        &logcid,
        &last_cnx);
  CHECK(send_rc == 0);
  if (state->bufuv.len <= 0) {
    free(state);
    return false;
  }

  DLOG("udp send %d bytes", state->bufuv.len);
  state->req.data = state;
  UV_CHECK(uv_udp_send(
        &state->req,
        &ctx->socket,
        &state->bufuv,
        1,
        (struct sockaddr*)&addr_peer,
        on_uv_send));
  return true;
}

static void quic_wakeup(uv_timer_t* timer) {
  client_ctx_t* ctx = (client_ctx_t*)timer->data;
  ctx->quic_wakeup = true;
}

void client_ctx_pqtimer_init(client_ctx_t* ctx) {
    uv_timer_init(ctx->loop, &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, quic_wakeup, 0, 10000);
    uv_run(ctx->loop, UV_RUN_ONCE);  // will run the callback immediately
    CHECK(ctx->quic_wakeup, "timer setup has to run first");
    ctx->quic_wakeup = false;
}

void client_ctx_pqtimer_tick(client_ctx_t* ctx) {
  if (ctx->shutdown) return;
  int64_t delay_max = 10000000;
  uint64_t current_time = picoquic_get_quic_time(ctx->quic);
  int64_t delta_t = picoquic_get_next_wake_delay(ctx->quic, current_time, delay_max);
  if (delta_t == 0) {
    quic_send(ctx);
  } else {
    uv_timer_set_repeat(&ctx->timer, delta_t / 1000);
    uv_timer_again(&ctx->timer);
    ctx->quic_wakeup = false;
  }
}

static int client_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t fin_or_event,
    void* callback_ctx,
    void* stream_ctx)
{
  (void)stream_id;

  client_ctx_t* client_ctx = (client_ctx_t*)callback_ctx;
  (void)client_ctx;
  client_stream_ctx_t* client_stream_ctx = (client_stream_ctx_t*)stream_ctx;
  DLOG("client_callback %d", fin_or_event);
  bool fin = fin_or_event == picoquic_callback_stream_fin;

  switch (fin_or_event) {
    /* Stateless reset received from peer, error message. Stream=0, bytes=NULL, len=0 */
    /* Received an error message */
    case picoquic_callback_stateless_reset:
    /* Application closed by peer. Stream=0, bytes=NULL, len=0 */
    case picoquic_callback_application_close:
    {
      LOG("quic connection error, closing");
      free(client_stream_ctx);
      picoquic_close(cnx, 0);
      break;
    }

    /* Data received from peer on stream N */
    case picoquic_callback_stream_data:
    /* Fin received from peer on stream N; data is optional */
    case picoquic_callback_stream_fin:
    {
      DLOG("quic recv %d bytes", length);
      DLOG("quic recv %.*s", length, bytes);
      if (fin) {
        LOG("quic connection done, closing");
        free(client_stream_ctx);
        picoquic_close(cnx, 0);
      }
      break;
    }

    /* Connection close. Stream=0, bytes=NULL, len=0 */
    case picoquic_callback_close:
    /* Datagram frame has been received */
    case picoquic_callback_datagram:
    /* Prepare the next datagram */
    case picoquic_callback_prepare_datagram:
    /* Ack for packet carrying datagram-frame received from peer */
    case picoquic_callback_datagram_acked:
    /* Packet carrying datagram-frame probably lost */
    case picoquic_callback_datagram_lost:
    /* Packet carrying datagram-frame was not really lost */
    case picoquic_callback_datagram_spurious:
      // TODO: datagram
      // picoquic_mark_datagram_ready
      // picoquic_provide_datagram_buffer
      // picoquic_set_default_datagram_priority
      // picoquic_set_datagram_priority
      // picoquic_queue_datagram_frame


    /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    case picoquic_callback_prepare_to_send:
      if (client_stream_ctx->sent) return 0;
      client_stream_ctx->sent = true;
      char* msg = "ping";
      size_t msg_len = 4;
      size_t left_to_send = msg_len;
      int is_fin = left_to_send <= length;
      CHECK(is_fin);
      size_t nsend = is_fin ? left_to_send : length;

      DLOG("quic send %d bytes", nsend);
      uint8_t* buf = picoquic_provide_stream_data_buffer(bytes, nsend, is_fin, !is_fin);
      CHECK(buf != NULL);
      memcpy(buf, msg, nsend);
      break;

    /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    case picoquic_callback_stream_reset:
    /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    case picoquic_callback_stop_sending:
      // TODO: client has terminated
      // picoquic_discard_stream

    /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
    case picoquic_callback_stream_gap:
    /* version negotiation requested */
    case picoquic_callback_version_negotiation:
    /* Data can be sent, but the connection is not fully established */
    case picoquic_callback_almost_ready:
    /* Data can be sent and received, connection migration can be initiated */
    case picoquic_callback_ready:
    /* Provide the list of supported ALPN */
    case picoquic_callback_request_alpn_list:
    /* Set ALPN to negotiated value */
    case picoquic_callback_set_alpn:
    /* Pacing rate for the connection changed */
    case picoquic_callback_pacing_changed:
    /* A new path is available, or a suspended path is available again */
    case picoquic_callback_path_available:
    /* An available path is suspended */
    case picoquic_callback_path_suspended:
    /* An existing path has been deleted */
    case picoquic_callback_path_deleted:
    /* Some path quality parameters have changed */
    case picoquic_callback_path_quality_changed:
      break;

    default:
      CHECK(false, "unknown event %d", fin_or_event);
      break;
  }
  return 0;
}

static void on_uv_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  (void)handle;
  void* bytes = malloc(suggested_size);
  buf->base = bytes;
  buf->len = suggested_size;
}

static void on_uv_read(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
  (void)flags;

  UV_CHECK(nread);
  client_ctx_t* ctx = (client_ctx_t*)handle->data;

  if (addr != NULL) {
    DLOG("udp recv %d bytes", nread);
    // Push received buffer into quic
    PQ_CHECK(picoquic_incoming_packet(
        ctx->quic,
        (uint8_t*)buf->base,
        nread,
        (struct sockaddr*)addr,
        (struct sockaddr*)&ctx->myaddr,
        0,  // if_index_to,
        0,  // received_ecn,
        picoquic_get_quic_time(ctx->quic)));
  } else {
    // no more data
    CHECK(nread == 0);
    free(buf->base);
  }

  // We check for messages to send here so that sends/recvs are interleaved
  quic_send(ctx);
}

static void loop_walk(uv_handle_t *handle, void *arg) {
  (void)arg;
  LOG("live handle: %s %p", uv_handle_type_name(handle->type), handle);
}

// static void loop_shutdown(uv_timer_t* timer) {
//   LOG("Loop shutdown requested");
//   client_ctx_t* ctx = (client_ctx_t*)timer->data;
//   ctx->shutdown = true;
//   uv_close((uv_handle_t*)timer, NULL);
//   uv_timer_stop(&ctx->timer);
//   uv_close((uv_handle_t*)&ctx->timer, NULL);
//   uv_udp_recv_stop(&ctx->socket);
//   uv_close((uv_handle_t*)&ctx->socket, NULL);
// }

void log_cxnid(picoquic_connection_id_t cid) {
    fprintf(stderr, "connection ID: ");
    for (uint8_t i = 0; i < cid.id_len; i++) {
        fprintf(stderr, "%02x", cid.id[i]);
    }
    fprintf(stderr, "\n");
}

void pq_log(const char *msg, void *argp) {
  (void)argp;
  LOG("%s", msg);
}

int client_main() {
  debug_set_callback(pq_log, NULL);

  client_ctx_t ctx = {0};

  // Loop setup
  uv_loop_t* loop = uv_default_loop();
  ctx.loop = loop;

  // QUIC setup
  ctx.quic = picoquic_create(
      8,
      NULL,  // cert
      NULL,  // key
      NULL,
      "picoquic-xos",  // alpn
      NULL,
      &ctx,
      NULL,
      NULL,
      NULL,
      picoquic_current_time(),
      NULL,
      NULL,
      NULL,
      0
  );
  CHECK(ctx.quic, "failed to create QUIC");
  picoquic_set_default_congestion_algorithm(ctx.quic, picoquic_bbr_algorithm);

  // QUIC timer setup
  client_ctx_pqtimer_init(&ctx);

  // QUIC client setup
  {
    // Create client connection
    struct sockaddr_in server_addr;
    uv_ip4_addr(SERVER_ADDR, SERVER_PORT, &server_addr);
    ctx.qclient = picoquic_create_client_cnx(
        ctx.quic,
        (struct sockaddr*)&server_addr,
        picoquic_current_time(),
        0,
        "test.example.com",  // sni
        "picoquic-xos",  // alpn
        client_callback,
        &ctx
    );
    CHECK(ctx.qclient != NULL);
    log_cxnid(picoquic_get_initial_cnxid(ctx.qclient));

    // Create client stream
    void* stream_ctx = calloc(sizeof(client_stream_ctx_t), 1);
    PQ_CHECK(picoquic_mark_active_stream(
          ctx.qclient,
          picoquic_get_next_local_stream_id(ctx.qclient, 0),
          1,  // is active
          stream_ctx));
  }

  // UDP setup
  UV_CHECK(uv_udp_init(loop, &ctx.socket));
  ctx.socket.data = &ctx;
  int len = 0;
  uv_udp_getsockname(&ctx.socket, (struct sockaddr*)&ctx.myaddr, &len);
  UV_CHECK(uv_udp_recv_start(&ctx.socket, on_uv_alloc, on_uv_read));

  // Shutdown in N seconds
  // uv_timer_t shutdown_timer;
  // uv_timer_init(loop, &shutdown_timer);
  // shutdown_timer.data = &ctx;
  // uv_timer_start(&shutdown_timer, loop_shutdown, 3000, 0);

  while (true) {
    client_ctx_pqtimer_tick(&ctx);
    bool live = (bool)uv_run(loop, UV_RUN_ONCE);
    bool sent = ctx.quic_wakeup && quic_send(&ctx);
    bool active = live || sent;
    if (!active) break;
  }

  LOG("Loop exited, shutting down");
  picoquic_delete_cnx(ctx.qclient);
  picoquic_free(ctx.quic);
  uv_walk(loop, loop_walk, NULL);
  UV_CHECK(uv_loop_close(loop));

  return 0;
}


typedef struct {
    picoquic_quic_t* quic;
    uv_loop_t* loop;
    uv_udp_t socket;
    struct sockaddr_in addr;
    uv_timer_t timer;
    bool quic_wakeup;
    bool shutdown;
} server_ctx_t;

typedef struct {
  uv_udp_send_t req;
  uv_buf_t bufuv;
  uint8_t buf[MAX_SEND_PACKET_SIZE];
} server_send_state_t;

static void server_on_uv_send(uv_udp_send_t *req, int status) {
  if (status < 0) {
    LOG("uv send fail: %s", uv_strerror(status));
  }

  server_send_state_t* state = (server_send_state_t*)req->data;
  free(state);
}

static bool server_quic_send(server_ctx_t* ctx) {
  server_send_state_t* state = (server_send_state_t*)malloc(sizeof(server_send_state_t));
  state->bufuv.base = (char*)state->buf;

  struct sockaddr_storage addr_local;
  struct sockaddr_storage addr_peer;
  int if_index = 0;
  picoquic_connection_id_t logcid;
  picoquic_cnx_t* last_cnx;
  int send_rc = picoquic_prepare_next_packet(
        ctx->quic,
        picoquic_get_quic_time(ctx->quic),
        state->buf,
        MAX_SEND_PACKET_SIZE,
        &state->bufuv.len,
        &addr_peer,
        &addr_local,
        &if_index,
        &logcid,
        &last_cnx);
  CHECK(send_rc == 0);
  if (state->bufuv.len <= 0) {
    free(state);
    return false;
  }

  DLOG("udp send %lu bytes", state->bufuv.len);
  state->req.data = state;
  UV_CHECK(uv_udp_send(
        &state->req,
        &ctx->socket,
        &state->bufuv,
        1,
        (struct sockaddr*)&addr_peer,
        server_on_uv_send));
  return true;
}

static void server_quic_wakeup(uv_timer_t* timer) {
  server_ctx_t* ctx = (server_ctx_t*)timer->data;
  ctx->quic_wakeup = true;
}

void server_ctx_pqtimer_init(server_ctx_t* ctx) {
    uv_timer_init(ctx->loop, &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, server_quic_wakeup, 0, 10000);
    uv_run(ctx->loop, UV_RUN_ONCE);  // will run the callback immediately
    CHECK(ctx->quic_wakeup, "timer setup has to run first");
    ctx->quic_wakeup = false;
}

void server_ctx_pqtimer_tick(server_ctx_t* ctx) {
  if (ctx->shutdown) return;
  int64_t delay_max = 10000000;
  uint64_t current_time = picoquic_get_quic_time(ctx->quic);
  int64_t delta_t = picoquic_get_next_wake_delay(ctx->quic, current_time, delay_max);
  if (delta_t == 0) {
    server_quic_send(ctx);
  } else {
    uv_timer_set_repeat(&ctx->timer, delta_t / 1000);
    uv_timer_again(&ctx->timer);
    ctx->quic_wakeup = false;
  }
}

static int server_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t fin_or_event,
    void* callback_ctx,
    void* stream_ctx) {
  (void)stream_ctx;
  DLOG("server_callback %d", fin_or_event);
  server_ctx_t* server_ctx = (server_ctx_t*)callback_ctx;
  (void)server_ctx;
  // stream_ctx never set, will be NULL
  // can set with
  // PQ_CHECK(picoquic_set_app_stream_ctx(cnx, stream_id, myctx));

  switch (fin_or_event) {
    /* Stateless reset received from peer, error message. Stream=0, bytes=NULL, len=0 */
    /* Received an error message */
    case picoquic_callback_stateless_reset:
    /* Connection close. Stream=0, bytes=NULL, len=0 */
    case picoquic_callback_close:
    /* Application closed by peer. Stream=0, bytes=NULL, len=0 */
    case picoquic_callback_application_close:
    {
      LOG("quic connection closed");
      break;
    }


    /* Fin received from peer on stream N; data is optional */
    case picoquic_callback_stream_fin:
    {
      DLOG("quic stream fin");
    }
    /* Data received from peer on stream N */
    case picoquic_callback_stream_data:
    {
      DLOG("quic recv %lu bytes", length);
      if (length > 0) {
        PQ_CHECK(picoquic_mark_active_stream(
              cnx,
              stream_id,
              1,  // is active
              NULL));
      }
      break;
    }

    /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    case picoquic_callback_prepare_to_send:
    {
      char* msg = "pong";
      size_t msg_len = 4;
      size_t left_to_send = msg_len;
      int is_fin = left_to_send <= length;
      CHECK(is_fin);
      size_t nsend = is_fin ? left_to_send : length;

      DLOG("quic send %lu bytes", nsend);
      uint8_t* buf = picoquic_provide_stream_data_buffer(bytes, nsend, is_fin, !is_fin);
      CHECK(buf != NULL);
      memcpy(buf, msg, nsend);
      break;
    }

    /* Datagram frame has been received */
    case picoquic_callback_datagram:
    /* Prepare the next datagram */
    case picoquic_callback_prepare_datagram:
    /* Ack for packet carrying datagram-frame received from peer */
    case picoquic_callback_datagram_acked:
    /* Packet carrying datagram-frame probably lost */
    case picoquic_callback_datagram_lost:
    /* Packet carrying datagram-frame was not really lost */
    case picoquic_callback_datagram_spurious:
      // TODO: datagram
      // picoquic_mark_datagram_ready
      // picoquic_provide_datagram_buffer
      // picoquic_set_default_datagram_priority
      // picoquic_set_datagram_priority
      // picoquic_queue_datagram_frame


    /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    case picoquic_callback_stream_reset:
    /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    case picoquic_callback_stop_sending:
      // TODO: client has terminated
      // picoquic_discard_stream


    /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
    case picoquic_callback_stream_gap:
    /* version negotiation requested */
    case picoquic_callback_version_negotiation:
    /* Data can be sent, but the connection is not fully established */
    case picoquic_callback_almost_ready:
    /* Data can be sent and received, connection migration can be initiated */
    case picoquic_callback_ready:
    /* Provide the list of supported ALPN */
    case picoquic_callback_request_alpn_list:
    /* Set ALPN to negotiated value */
    case picoquic_callback_set_alpn:
    /* Pacing rate for the connection changed */
    case picoquic_callback_pacing_changed:
    /* A new path is available, or a suspended path is available again */
    case picoquic_callback_path_available:
    /* An available path is suspended */
    case picoquic_callback_path_suspended:
    /* An existing path has been deleted */
    case picoquic_callback_path_deleted:
    /* Some path quality parameters have changed */
    case picoquic_callback_path_quality_changed:
      break;

    default:
      CHECK(false, "unknown event %d", fin_or_event);
      break;
  }
  return 0;
}

static void server_on_uv_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  (void)handle;
  void* bytes = malloc(suggested_size);
  buf->base = bytes;
  buf->len = suggested_size;
}

static void server_on_uv_read(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
  (void)flags;
  UV_CHECK(nread);
  server_ctx_t* ctx = (server_ctx_t*)handle->data;

  if (addr != NULL) {
    DLOG("udp recv %lu bytes", nread);
    // Push received buffer into quic
    PQ_CHECK(picoquic_incoming_packet(
        ctx->quic,
        (uint8_t*)buf->base,
        nread,
        (struct sockaddr*)addr,
        (struct sockaddr*)&ctx->addr,
        0,  // if_index_to,
        0,  // received_ecn,
        picoquic_get_quic_time(ctx->quic)));

    // We check for messages to send here so that sends/recvs are interleaved
    server_quic_send(ctx);
  } else {
    // no more data
    CHECK(nread == 0);
    free(buf->base);
  }
}

int server_main() {
    debug_set_callback(pq_log, NULL);

    server_ctx_t ctx = {0};

    // Loop setup
    uv_loop_t* loop = uv_default_loop();
    ctx.loop = loop;

    // QUIC setup
    ctx.quic = picoquic_create(
        8,
        SERVER_CERT,
        SERVER_KEY,
        NULL,
        "picoquic-xos",  // alpn
        server_callback,
        &ctx,
        NULL,
        NULL,
        NULL,
        picoquic_current_time(),
        NULL,
        NULL,
        NULL,
        0);
    CHECK(ctx.quic, "failed to create QUIC");
    picoquic_set_cookie_mode(ctx.quic, 2);
    picoquic_set_default_congestion_algorithm(ctx.quic, picoquic_bbr_algorithm);
    PQ_CHECK(picoquic_set_cipher_suite(ctx.quic, PICOQUIC_CHACHA20_POLY1305_SHA256));
    picoquic_set_client_authentication(ctx.quic, 1);

    // QUIC timer setup
    server_ctx_pqtimer_init(&ctx);

    // UDP setup
    UV_CHECK(uv_udp_init_ex(loop, &ctx.socket, UV_UDP_RECVMMSG));
    ctx.socket.data = &ctx;
    uv_ip4_addr("0.0.0.0", SERVER_PORT, &ctx.addr);
    UV_CHECK(uv_udp_bind(&ctx.socket, (const struct sockaddr*)&ctx.addr, 0));

    // Start listening
    UV_CHECK(uv_udp_recv_start(&ctx.socket, server_on_uv_alloc, server_on_uv_read));
    LOG("Server listening on port %d", SERVER_PORT);

    // Shutdown in N seconds
    // uv_timer_t shutdown_timer;
    // uv_timer_init(loop, &shutdown_timer);
    // shutdown_timer.data = &ctx;
    // uv_timer_start(&shutdown_timer, loop_shutdown, 3000, 0);

    while (true) {
      server_ctx_pqtimer_tick(&ctx);
      bool live = (bool)uv_run(loop, UV_RUN_ONCE);
      bool sent = ctx.quic_wakeup && server_quic_send(&ctx);
      bool active = live || sent;
      if (!active) break;
    }

    LOG("Loop exited, shutting down");
    picoquic_free(ctx.quic);
    uv_walk(loop, loop_walk, NULL);
    UV_CHECK(uv_loop_close(loop));

    return 0;
}

int main(int argc, char** argv) {
  if (argc < 2)
    abort();
  bool client = argv[1][0] == 'c';
  if (client)
    return client_main();
  else
    return server_main();
}
