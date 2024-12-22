#include "tcp2.h"

#include "sodium.h"
#include "stdnet.h"
#include "stdtime.h"

#define TCP2_CIDLEN          NGTCP2_MAX_CIDLEN  // 20
#define TCP2_STREAM_DATAGRAM -2

// https://nghttp2.org/ngtcp2/programmers-guide.html

void        tcp2_set_crypto_callbacks(ngtcp2_callbacks* cb, bool client);
static void tcp2_set_callbacks(ngtcp2_callbacks* cb, Tcp2RecvCbs recv,
                               bool client);

static Tcp2Msg* tcp2_msgq_dequeue(Queue* q) {
  Node* n = q_deq(q);
  if (n == 0)
    return 0;
  return CONTAINER_OF(n, Tcp2Msg, next);
}

static void tcp2_outgoing_free(Tcp2Ctx* ctx) {
  Tcp2Msg* msg;
  while ((msg = tcp2_msgq_dequeue(&ctx->outgoing))) {
    Alloc_destroy(ctx->allocator, msg);
  }
}

static void tcp2_sent_free(Tcp2Ctx* ctx) {
  Tcp2Msg* msg;

  i64*   stream;
  Queue* q;

  (void)stream;

  hashmap_foreach(&ctx->sent, stream, q, {
    while ((msg = tcp2_msgq_dequeue(q)))
      Alloc_destroy(ctx->allocator, msg);
  });
}

static int tcp2_get_new_connection_id(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                      uint8_t* token, size_t cidlen,
                                      void* user_data) {
  randombytes_buf(cid->data, cidlen);
  cid->datalen = cidlen;
  randombytes_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

static int tcp2_get_path_challenge_data(ngtcp2_conn* conn, uint8_t* data,
                                        void* user_data) {
  randombytes_buf(data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

int tcp2_acked_stream_data_offset(ngtcp2_conn* conn, int64_t stream_id,
                                  uint64_t offset, uint64_t datalen,
                                  void* user_data, void* stream_user_data) {
  // data[offset..offset+datalen] has been acknowledged, can free
  Tcp2Ctx* ctx = user_data;

  HashmapIter it = hashmap_get(&ctx->sent, &stream_id);
  if (it == hashmap_end(&ctx->sent))
    return -1;

  Queue*   q = hashmap_val(&ctx->sent, it);
  Node*    n;
  Tcp2Msg* msg;
  while (datalen && (n = q->head)) {
    msg          = CONTAINER_OF(n, Tcp2Msg, next);
    usize nacked = MIN(msg->data.len, datalen);
    msg->_offset -= nacked;
    datalen -= nacked;
    if (msg->_offset == 0) {
      Tcp2Msg* acked = tcp2_msgq_dequeue(q);
      Alloc_destroy(ctx->allocator, acked);
    }
  }

  return 0;
}

void tcp2_log_printf(void* user_data, const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

void* tcp2_allocator_malloc(size_t size, void* user_data) {
  Allocator* alloc = user_data;
  Bytes      mem   = {0};
  if (allocator_u8(*alloc, &mem, size))
    return 0;
  return mem.buf;
}

void* tcp2_allocator_calloc(size_t nmemb, size_t size, void* user_data) {
  void* p = tcp2_allocator_malloc(nmemb * size, user_data);
  if (p == NULL)
    return p;
  memset(p, 0, nmemb * size);
  return p;
}

void* tcp2_allocator_realloc(void* ptr, size_t size, void* user_data) {
  Allocator* alloc = user_data;
  Bytes      mem   = Bytes(ptr, 0);
  if (allocator_realloc(*alloc, &mem, size, 8))
    return 0;
  return mem.buf;
}

void tcp2_allocator_free(void* p, void* user_data) {
  Allocator* alloc = user_data;
  Bytes      mem   = Bytes(p, 1);
  allocator_free(*alloc, mem);
}

ngtcp2_mem tcp2_allocator(Allocator* alloc) {
  ngtcp2_mem mem = {0};
  mem.user_data  = alloc;
  mem.malloc     = tcp2_allocator_malloc;
  mem.free       = tcp2_allocator_free;
  mem.realloc    = tcp2_allocator_realloc;
  mem.calloc     = tcp2_allocator_calloc;
  return mem;
}

void tcp2_transport_params_default(ngtcp2_transport_params* params) {
  ngtcp2_transport_params_default(params);
  params->initial_max_streams_bidi            = 128;
  params->initial_max_streams_uni             = 128;
  params->initial_max_stream_data_bidi_local  = 128;
  params->initial_max_stream_data_bidi_remote = 128;
  params->initial_max_stream_data_uni         = 128;
  params->initial_max_data                    = 1 << 30;
  params->max_datagram_frame_size             = 1200;
}

static void tcp2_set_callbacks(ngtcp2_callbacks* cb, Tcp2RecvCbs recv,
                               bool client) {
  tcp2_set_crypto_callbacks(cb, client);
  cb->get_new_connection_id    = tcp2_get_new_connection_id;
  cb->get_path_challenge_data  = tcp2_get_path_challenge_data;
  cb->acked_stream_data_offset = tcp2_acked_stream_data_offset;
  cb->recv_stream_data         = recv.stream;
  cb->recv_datagram            = recv.datagram;
}

void tcp2_outgoing_enqueue(Tcp2Ctx* ctx, Bytes data, i64 stream) {
  Tcp2Msg* node;
  CHECK0(Alloc_create(ctx->allocator, &node));
  node->data   = data;
  node->stream = stream;
  q_enq(&ctx->outgoing, &node->next);
}

int tcp2_outgoing_process(Tcp2Ctx* ctx, Bytes* pkt, u64 now, u64 bytes) {
  if (pkt->len != NGTCP2_MAX_UDP_PAYLOAD_SIZE)
    return -1;

  ngtcp2_ssize stream_write;
  Tcp2Msg*     msg      = 0;
  Node*        n        = 0;
  bool         pkt_full = false;
  u64          maxbytes = ngtcp2_conn_get_send_quantum(ctx->conn);

  while (!pkt_full && bytes < maxbytes && (n = ctx->outgoing.head)) {
    msg = CONTAINER_OF(n, Tcp2Msg, next);

    u8* data    = msg->data.buf + msg->_offset;
    u64 datalen = msg->data.len - msg->_offset;

    ngtcp2_ssize sz;
    if (msg->stream == TCP2_STREAM_DATAGRAM) {
      sz = ngtcp2_conn_write_datagram(ctx->conn, 0, 0, pkt->buf, pkt->len, 0,
                                      NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, data,
                                      datalen, now);
    } else {
      sz = ngtcp2_conn_write_stream(
          ctx->conn, 0, 0, pkt->buf, pkt->len, &stream_write,
          NGTCP2_WRITE_STREAM_FLAG_MORE, msg->stream, data, datalen, now);
    }

    if (sz == NGTCP2_ERR_WRITE_MORE || sz >= 0) {
      if (sz != NGTCP2_ERR_WRITE_MORE)
        pkt_full = true;

      msg->_offset += stream_write;
      bytes += sz;
      if (msg->_offset == msg->data.len) {
        Tcp2Msg* done = tcp2_msgq_dequeue(&ctx->outgoing);
        if (done->stream == TCP2_STREAM_DATAGRAM) {
          // All done, no need to wait for ack
          Alloc_destroy(ctx->allocator, done);
        } else {
          // Add the message to the sent queue to hold onto it until ack
          HashmapStatus s  = 0;
          HashmapIter   it = hashmap_put(&ctx->sent, &msg->stream, &s);
          if (it == hashmap_end(&ctx->sent)) {
            CHECK(false, "oom");
            return -1;
          }

          Queue* sent = hashmap_val(&ctx->sent, it);
          if (s != HashmapStatus_Present)
            *sent = (Queue){0};

          q_enq(sent, &done->next);
        }
      }
    } else if (sz < 0) {
      CHECK_TCP2(sz);
      // TODO:
      // error
      // what about dequeued packets?
      // maybe collect up the errors so that not everything fails
      return (int)sz;
    }
  }

  ngtcp2_ssize sz =
      ngtcp2_conn_write_pkt(ctx->conn, 0, 0, pkt->buf, pkt->len, now);
  if (sz < 0)
    return (int)sz;
  pkt->len = sz;

  ngtcp2_conn_update_pkt_tx_time(ctx->conn, now);
  return 0;
}

int tcp2_accept(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes pkt, Bytes* resp,
                Tcp2RecvCbs recv_cbs, Allocator allocator, u64 now) {
  *ctx = (Tcp2Ctx){0};

  ctx->allocator = allocator;
  if (Hashmap_i64_create(&ctx->sent, Queue, ctx->allocator))
    return -1;

  int rc = 0;

  ngtcp2_pkt_hd hd;
  rc = ngtcp2_accept(&hd, pkt.buf, pkt.len);
  if (rc != 0)
    return rc;

  ngtcp2_cid scid = {0};
  scid.datalen    = TCP2_CIDLEN;
  randombytes_buf(scid.data, scid.datalen);

  ngtcp2_callbacks callbacks = {0};
  tcp2_set_callbacks(&callbacks, recv_cbs, false);
  ngtcp2_transport_params tparams = {0};
  tcp2_transport_params_default(&tparams);
  tparams.original_dcid         = hd.dcid;
  tparams.original_dcid_present = 1;
  ngtcp2_settings settings      = {0};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now;
  // settings.log_printf = tcp2_log_printf;
  (void)tcp2_log_printf;

  ctx->mem = tcp2_allocator(&ctx->allocator);

  ngtcp2_conn** server = &ctx->conn;
  rc = ngtcp2_conn_server_new(server, &hd.scid, &scid, path, hd.version,
                              &callbacks, &settings, &tparams, &ctx->mem, ctx);
  if (rc != 0)
    return rc;

  ctx->conn = *server;

  rc = ngtcp2_conn_read_pkt(*server, path, 0, pkt.buf, pkt.len,
                            settings.initial_ts);
  if (rc != 0) {
    ngtcp2_conn_del(*server);
    return rc;
  }

  if (allocator_u8(ctx->allocator, resp, NGTCP2_MAX_UDP_PAYLOAD_SIZE))
    return -1;
  rc = tcp2_outgoing_process(ctx, resp, now, 0);
  if (rc != 0) {
    allocator_free(ctx->allocator, *resp);
    ngtcp2_conn_del(*server);
    return rc;
  }

  return 0;
}

int tcp2_connect(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes* pkt,
                 const Tcp2ZeroRTT* zerortt,

                 Tcp2RecvCbs recv_cbs, Allocator allocator, u64 now) {
  *ctx           = (Tcp2Ctx){0};
  ctx->allocator = allocator;
  if (Hashmap_i64_create(&ctx->sent, Queue, allocator))
    return -1;

  ngtcp2_cid scid = {0};
  scid.datalen    = TCP2_CIDLEN;
  randombytes_buf(scid.data, scid.datalen);
  ngtcp2_cid dcid = {0};
  dcid.datalen    = TCP2_CIDLEN;
  randombytes_buf(dcid.data, dcid.datalen);
  ngtcp2_callbacks callbacks = {0};
  tcp2_set_callbacks(&callbacks, recv_cbs, true);
  ngtcp2_transport_params tparams = {0};
  tcp2_transport_params_default(&tparams);
  ngtcp2_settings settings = {0};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now;
  // settings.log_printf = tcp2_log_printf;
  (void)tcp2_log_printf;

  ngtcp2_conn** client = &ctx->conn;
  ctx->mem             = tcp2_allocator(&ctx->allocator);

  int rc = 0;
  rc = ngtcp2_conn_client_new(client, &dcid, &scid, path, NGTCP2_PROTO_VER_V1,
                              &callbacks, &settings, &tparams, &ctx->mem, ctx);
  if (rc != 0)
    return rc;

  ctx->conn = *client;

  if (zerortt && zerortt->params_len) {
    rc = ngtcp2_conn_decode_and_set_0rtt_transport_params(
        *client, zerortt->params_buf, zerortt->params_len);
    if (rc != 0)
      return rc;

    if (zerortt->data.len) {
      i64 stream;
      rc = ngtcp2_conn_open_bidi_stream(*client, &stream, ctx);
      if (rc != 0)
        return rc;
      tcp2_outgoing_enqueue(ctx, zerortt->data, stream);
    }
  }

  // Send
  if (allocator_u8(ctx->allocator, pkt, NGTCP2_MAX_UDP_PAYLOAD_SIZE))
    return -1;
  rc = tcp2_outgoing_process(ctx, pkt, now, 0);
  if (rc != 0) {
    allocator_free(ctx->allocator, *pkt);
    ngtcp2_conn_del(*client);
    return rc;
  }
  return 0;
}

void tcp2_conn_deinit(Tcp2Ctx* ctx) {
  ngtcp2_conn_del(ctx->conn);
  tcp2_outgoing_free(ctx);
  tcp2_sent_free(ctx);
  hashmap_deinit(&ctx->sent);
  *ctx = (Tcp2Ctx){0};
}

ngtcp2_addr tcp2_ipv4(const char* host, u16 port,
                      ngtcp2_sockaddr_union* addru) {
  ngtcp2_addr addr = {&addru->sa, sizeof(addru->in)};
  stdnet_sockaddr_ip4(&addru->sa, host, port);
  return addr;
}

ngtcp2_addr tcp2_ipv6(const char* host, u16 port,
                      ngtcp2_sockaddr_union* addru) {
  ngtcp2_addr addr = {&addru->sa, sizeof(addru->in6)};
  stdnet_sockaddr_ip6(&addru->sa, host, port);
  return addr;
}
