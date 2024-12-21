#include "stdtypes.h"
#include "hashmap.h"
#include "allocatormi.h"

#include "sodium.h"
#include "uv.h"
#include "ngtcp2/ngtcp2.h"

#define TCP2_LOCALHOST       "127.0.0.1"
#define TCP2_LOCALHOST6      "::1"
#define TCP2_CIDLEN          NGTCP2_MAX_CIDLEN  // 20
#define TCP2_STREAM_DATAGRAM -2
#define CHECK_TCP2(s)                                                          \
  do {                                                                         \
    int __rc = (int)(s);                                                       \
    CHECK(__rc >= 0, "%s: rc=%d %s", #s, __rc, ngtcp2_strerror(__rc));         \
  } while (0)

typedef struct Tcp2Msg {
  Bytes data;
  i64   stream;  // TCP2_STREAM_*, or from ngtcp2_conn_open_{bidi,uni}_stream
  struct Tcp2Msg* _next;
  usize           _offset;
} Tcp2Msg;

typedef struct {
  Tcp2Msg* head;
  Tcp2Msg* tail;
} Tcp2MsgQ;

typedef struct {
  u8    buf[256];
  usize len;
  Bytes data;
} Tcp2ZeroRTT;

typedef struct {
  ngtcp2_conn* conn;
  Allocator    allocator;
  ngtcp2_mem   mem;
  Tcp2MsgQ     outgoing;
  Hashmap      sent;  // i64 -> Tcp2MsgQ
  Tcp2ZeroRTT  zerortt;
} Tcp2Ctx;

static void tcp2_zerortt_save(Tcp2Ctx* ctx, Bytes params) {
  memcpy(ctx->zerortt.buf, params.buf, params.len);
  ctx->zerortt.len = params.len;
}

static void tcp2_msgq_enqueue(Tcp2MsgQ* q, Tcp2Msg* node) {
  node->_next = 0;
  if (q->tail) {
    q->tail->_next = node;
  } else {
    q->head = node;
    q->tail = node;
  }
}

static void tcp2_outgoing_enqueue(Tcp2Ctx* ctx, Bytes data, i64 stream) {
  Tcp2Msg* node;
  CHECK0(Alloc_create(ctx->allocator, &node));
  node->data   = data;
  node->stream = stream;
  tcp2_msgq_enqueue(&ctx->outgoing, node);
}

static Tcp2Msg* tcp2_msgq_dequeue(Tcp2MsgQ* q) {
  if (q->head == 0)
    return 0;

  Tcp2Msg* msg = q->head;
  if (q->head == q->tail) {
    q->head = 0;
    q->tail = 0;
    return msg;
  }

  q->head = msg->_next;
  return msg;
}

static void tcp2_outgoing_free(Tcp2Ctx* ctx) {
  Tcp2Msg* msg;
  while ((msg = tcp2_msgq_dequeue(&ctx->outgoing))) {
    Alloc_destroy(ctx->allocator, msg);
  }
}

static void tcp2_sent_free(Tcp2Ctx* ctx) {
  Tcp2Msg* msg;

  i64*      stream;
  Tcp2MsgQ* q;

  (void)stream;

  hashmap_foreach(&ctx->sent, stream, q, {
    while ((msg = tcp2_msgq_dequeue(q)))
      Alloc_destroy(ctx->allocator, msg);
  });
}

typedef struct {
  u8                       secret[1];
  u8                       iv[8];
  ngtcp2_crypto_aead_ctx   aead;
  ngtcp2_crypto_cipher_ctx cipher;
  ngtcp2_crypto_ctx        ctx;
} Tcp2Key;

#define TCP2_AEAD_OVERHEAD crypto_aead_chacha20poly1305_IETF_ABYTES  // 16

static Tcp2Key tcp2_crypto_key(void) {
  Tcp2Key key                    = {0};
  key.aead.native_handle         = (void*)1;
  key.cipher.native_handle       = (void*)1;
  key.ctx.aead.native_handle     = (void*)1;
  key.ctx.aead.max_overhead      = TCP2_AEAD_OVERHEAD;
  key.ctx.md.native_handle       = (void*)1;
  key.ctx.hp.native_handle       = (void*)1;
  key.ctx.max_encryption         = UINT64_MAX;
  key.ctx.max_decryption_failure = 128;
  return key;
}

static int tcp2_crypto_rw(ngtcp2_conn*            conn,
                          ngtcp2_encryption_level encryption_level,
                          const uint8_t* data, size_t datalen,
                          void* user_data) {
  // TODO: ngtcp2_conn_set_tls_error on error
  LOG("level=%d", encryption_level);
  Tcp2Ctx* ctx = user_data;
  int      rc;

  if (ngtcp2_conn_is_server(conn)) {
    // Server
    switch (encryption_level) {
      case NGTCP2_ENCRYPTION_LEVEL_INITIAL: {
        // Respond to client initial message

        // Set remote transport params
        {
          u8 tparams_len = data[0];
          rc             = ngtcp2_conn_decode_and_set_remote_transport_params(
              conn, &data[1], tparams_len);
          if (rc != 0)
            return -1;
          CHECK(ngtcp2_conn_get_negotiated_version(conn));
        }

        // Ack the initial message
        {
          Str resp = Str("ack");
          rc       = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, resp.buf, resp.len);
          if (rc != 0)
            return rc;
        }

        // Install 0RTT key
        {
          Tcp2Key rx = tcp2_crypto_key();
          ngtcp2_conn_set_0rtt_crypto_ctx(conn, &rx.ctx);
          rc = ngtcp2_conn_install_0rtt_key(conn, &rx.aead, rx.iv,
                                            sizeof(rx.iv), &rx.cipher);
          if (rc != 0)
            return -1;
        }

        // Install the handshake keys
        {
          Tcp2Key tx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_tx_handshake_key(conn, &tx.aead, tx.iv,
                                                    sizeof(tx.iv), &tx.cipher);
          if (rc != 0)
            return -1;
          Tcp2Key rx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_rx_handshake_key(conn, &rx.aead, rx.iv,
                                                    sizeof(rx.iv), &rx.cipher);
          if (rc != 0)
            return -1;
          ngtcp2_conn_set_crypto_ctx(conn, &tx.ctx);
        }

        // Send the handshake message with transport params + 0rtt params
        {
          u8    respbuf[512] = {0};
          usize respi        = 0;

          // Transport params
          {
            ngtcp2_ssize nwrite = ngtcp2_conn_encode_local_transport_params(
                conn, &respbuf[1], 255);
            if (nwrite < 0)
              return -1;
            respbuf[respi++] = (u8)nwrite;
            respi += (u8)nwrite;
          }

          // 0RTT Transport params
          {
            ngtcp2_ssize nwrite = ngtcp2_conn_encode_0rtt_transport_params(
                conn, &respbuf[respi + 1], 255);
            if (nwrite < 0)
              return -1;
            respbuf[respi++] = (u8)nwrite;
            respi += (u8)nwrite;
          }
          rc = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, respbuf, respi);
          if (rc != 0)
            return rc;
        }

        // Install the txrx keys
        {
          Tcp2Key tx = tcp2_crypto_key();
          Tcp2Key rx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_tx_key(conn, tx.secret, sizeof(tx.secret),
                                          &tx.aead, tx.iv, sizeof(tx.iv),
                                          &tx.cipher);
          if (rc != 0)
            return -1;
          rc = ngtcp2_conn_install_rx_key(conn, rx.secret, sizeof(rx.secret),
                                          &rx.aead, rx.iv, sizeof(rx.iv),
                                          &rx.cipher);
          if (rc != 0)
            return -1;
          ngtcp2_conn_set_crypto_ctx(conn, &tx.ctx);
        }

        break;
      }

      case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE: {
        ngtcp2_conn_tls_handshake_completed(conn);
        LOG("server handshake completed");
        break;
      }

      case NGTCP2_ENCRYPTION_LEVEL_1RTT:
        // unexpected, tcp2 never sends at this level
        break;
      case NGTCP2_ENCRYPTION_LEVEL_0RTT:
        // unexpected, ngtcp2 never sends at this level
        break;
    }
  } else {
    // Client
    switch (encryption_level) {
      case NGTCP2_ENCRYPTION_LEVEL_INITIAL: {
        if (data == NULL) {
          // First message out

          // Install initial keys
          {
            Tcp2Key rx = tcp2_crypto_key();
            Tcp2Key tx = tcp2_crypto_key();
            ngtcp2_conn_set_initial_crypto_ctx(conn, &rx.ctx);
            rc = ngtcp2_conn_install_initial_key(conn, &rx.aead, rx.iv,
                                                 &rx.cipher, &tx.aead, tx.iv,
                                                 &tx.cipher, sizeof(rx.iv));
            if (rc != 0)
              return rc;
          }

          // Encode local transport params
          {
            u8           databuf[256] = {0};
            ngtcp2_ssize nwrite = ngtcp2_conn_encode_local_transport_params(
                conn, &databuf[1], 255);
            if (nwrite < 0)
              return -1;
            databuf[0]    = (u8)nwrite;
            usize datalen = (u8)nwrite + 1;
            rc            = ngtcp2_conn_submit_crypto_data(
                conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, databuf, datalen);
            if (rc != 0)
              return rc;
          }

          // Install 0RTT key
          {
            Tcp2Key tx = tcp2_crypto_key();
            ngtcp2_conn_set_0rtt_crypto_ctx(conn, &tx.ctx);
            rc = ngtcp2_conn_install_0rtt_key(conn, &tx.aead, tx.iv,
                                              sizeof(tx.iv), &tx.cipher);
            if (rc != 0)
              return -1;
          }
        } else {
          // Server response

          LOG("server crypto repsonse arrived");
          Tcp2Key rx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_rx_handshake_key(conn, &rx.aead, rx.iv,
                                                    sizeof(rx.iv), &rx.cipher);
          if (rc != 0)
            return -1;
          Tcp2Key tx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_tx_handshake_key(conn, &tx.aead, tx.iv,
                                                    sizeof(tx.iv), &tx.cipher);
          if (rc != 0)
            return -1;
          ngtcp2_conn_set_crypto_ctx(conn, &tx.ctx);
        }

        break;
      }
      case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
        LOG("server handshake msg arrived");
        // Set transport params
        {
          rc = ngtcp2_conn_decode_and_set_remote_transport_params(
              conn, &data[1], data[0]);
          if (rc != 0)
            return -1;
        }

        // Save 0RTT params
        {
          usize i = data[0] + 1;  // skip over transport params
          tcp2_zerortt_save(ctx, Bytes(&data[i + 1], data[i]));
        }

        // Ack
        {
          Str data = Str("ok");
          rc       = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, data.buf, data.len);
          if (rc != 0)
            return rc;
        }

        // Mark complete
        {
          Tcp2Key rx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_rx_key(conn, rx.secret, sizeof(rx.secret),
                                          &rx.aead, rx.iv, sizeof(rx.iv),
                                          &rx.cipher);
          if (rc != 0)
            return -1;
          Tcp2Key tx = tcp2_crypto_key();
          rc = ngtcp2_conn_install_tx_key(conn, tx.secret, sizeof(tx.secret),
                                          &tx.aead, tx.iv, sizeof(tx.iv),
                                          &tx.cipher);
          if (rc != 0)
            return -1;
          ngtcp2_conn_set_crypto_ctx(conn, &tx.ctx);
          ngtcp2_conn_tls_handshake_completed(conn);
          LOG("client handshake completed");
        }

        break;
      case NGTCP2_ENCRYPTION_LEVEL_1RTT:
        // unexpected, tcp2 never sends at this level
        break;
      case NGTCP2_ENCRYPTION_LEVEL_0RTT:
        // unexpected, ngtcp2 never sends at this level
        break;
    }
  }

  return 0;
}

static int tcp2_client_initial(ngtcp2_conn* conn, void* user_data) {
  LOG("");
  return tcp2_crypto_rw(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, 0, 0, user_data);
}

static int tcp2_recv_retry(ngtcp2_conn* conn, const ngtcp2_pkt_hd* hd,
                           void* user_data) {
  LOG("");
  return tcp2_client_initial(conn, user_data);
}

static int tcp2_recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid,
                                    void* user_data) {
  LOG("");
  Tcp2Ctx* ctx = user_data;
  (void)ctx;
  Tcp2Key rx = tcp2_crypto_key();
  Tcp2Key tx = tcp2_crypto_key();
  ngtcp2_conn_set_initial_crypto_ctx(conn, &rx.ctx);
  return ngtcp2_conn_install_initial_key(conn, &rx.aead, rx.iv, &rx.cipher,
                                         &tx.aead, tx.iv, &tx.cipher,
                                         sizeof(rx.iv));
}

static int tcp2_recv_crypto_data(ngtcp2_conn*            conn,
                                 ngtcp2_encryption_level encryption_level,
                                 uint64_t offset, const uint8_t* data,
                                 size_t datalen, void* user_data) {
  LOG("");
  return tcp2_crypto_rw(conn, encryption_level, data, datalen, user_data);
}

static int tcp2_encrypt(uint8_t* dest, const ngtcp2_crypto_aead* aead,
                        const ngtcp2_crypto_aead_ctx* aead_ctx,
                        const uint8_t* plaintext, size_t plaintextlen,
                        const uint8_t* nonce, size_t noncelen,
                        const uint8_t* aad, size_t aadlen) {
  // Note: dest may be plaintext, in-place encryption
  LOG("");

  memmove(dest + TCP2_AEAD_OVERHEAD, plaintext, plaintextlen);
  memset(dest, 2, TCP2_AEAD_OVERHEAD);

  return 0;
}

static int tcp2_decrypt(uint8_t* dest, const ngtcp2_crypto_aead* aead,
                        const ngtcp2_crypto_aead_ctx* aead_ctx,
                        const uint8_t* ciphertext, size_t ciphertextlen,
                        const uint8_t* nonce, size_t noncelen,
                        const uint8_t* aad, size_t aadlen) {
  // Note: dest may be ciphertext, in-place decryption
  memmove(dest, ciphertext + TCP2_AEAD_OVERHEAD,
          ciphertextlen - TCP2_AEAD_OVERHEAD);
  return 0;
}

static int tcp2_hp_mask(uint8_t* dest, const ngtcp2_crypto_cipher* hp,
                        const ngtcp2_crypto_cipher_ctx* hp_ctx,
                        const uint8_t*                  sample) {
  LOG("");
  memset(dest, 3, NGTCP2_HP_MASKLEN);
  return 0;
}

static void tcp2_rand(uint8_t* dest, size_t destlen,
                      const ngtcp2_rand_ctx* rand_ctx) {
  (void)rand_ctx;
  randombytes_buf(dest, destlen);
}

static int tcp2_get_new_connection_id(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                      uint8_t* token, size_t cidlen,
                                      void* user_data) {
  LOG("");
  randombytes_buf(cid->data, cidlen);
  cid->datalen = cidlen;
  randombytes_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

static int tcp2_update_key(ngtcp2_conn* conn, uint8_t* rx_secret,
                           uint8_t*                tx_secret,
                           ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                           ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                           const uint8_t* current_rx_secret,
                           const uint8_t* current_tx_secret, size_t secretlen,
                           void* user_data) {
  LOG("");
  return 0;
}

static void tcp2_delete_crypto_aead_ctx(ngtcp2_conn*            conn,
                                        ngtcp2_crypto_aead_ctx* aead_ctx,
                                        void*                   user_data) {
  LOG("");
}

static void tcp2_delete_crypto_cipher_ctx(ngtcp2_conn*              conn,
                                          ngtcp2_crypto_cipher_ctx* cipher_ctx,
                                          void*                     user_data) {
  LOG("");
}

static int tcp2_get_path_challenge_data(ngtcp2_conn* conn, uint8_t* data,
                                        void* user_data) {
  LOG("");
  randombytes_buf(data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

static int tcp2_version_negotiation(ngtcp2_conn* conn, uint32_t version,
                                    const ngtcp2_cid* client_dcid,
                                    void*             user_data) {
  LOG("");
  Tcp2Ctx* ctx = user_data;
  (void)ctx;

  int     rc = 0;
  Tcp2Key rx = tcp2_crypto_key();
  Tcp2Key tx = tcp2_crypto_key();
  rc = ngtcp2_conn_install_vneg_initial_key(conn, version, &rx.aead, rx.iv,
                                            &rx.cipher, &tx.aead, tx.iv,
                                            &tx.cipher, sizeof(rx.iv));
  if (rc != 0)
    return rc;

  return rc;
}

static int tcp2_recv_datagram(ngtcp2_conn* conn, uint32_t flags,
                              const uint8_t* data, size_t datalen,
                              void* user_data) {
  LOG("");
  // NGTCP2_DATAGRAM_FLAG_0RTT

  Tcp2Ctx* ctx = user_data;
  (void)ctx;

  return 0;
}

static int tcp2_recv_stream_data(ngtcp2_conn* conn, uint32_t flags,
                                 int64_t stream_id, uint64_t offset,
                                 const uint8_t* data, size_t datalen,
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

static int tcp2_handshake_confirmed(ngtcp2_conn* conn, void* user_data) {
  LOG("");
  return 0;
}

static int tcp2_handshake_completed(ngtcp2_conn* conn, void* user_data) {
  // for client, completed, but not confirmed
  // for server, completed and confirmed
  LOG("");
  bool server = ngtcp2_conn_is_server(conn);
  if (server)
    return tcp2_handshake_confirmed(conn, user_data);
  return 0;
}

static int tcp2_acked_stream_data_offset(ngtcp2_conn* conn, int64_t stream_id,
                                         uint64_t offset, uint64_t datalen,
                                         void* user_data,
                                         void* stream_user_data) {
  // data[offset..offset+datalen] has been acknowledged, can free
  LOG("");

  Tcp2Ctx* ctx = user_data;

  HashmapIter it = hashmap_get(&ctx->sent, &stream_id);
  if (it == hashmap_end(&ctx->sent))
    return -1;

  Tcp2MsgQ* q = hashmap_val(&ctx->sent, it);
  Tcp2Msg*  msg;
  while (datalen && (msg = q->head)) {
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

static void tcp2_log_printf(void* user_data, const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

static u64 tcp2_current_time() {
  uv_timespec64_t sp;
  uv_clock_gettime(UV_CLOCK_MONOTONIC, &sp);
  return sp.tv_sec * NGTCP2_SECONDS + sp.tv_nsec;
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

static ngtcp2_mem tcp2_allocator(Allocator* alloc) {
  ngtcp2_mem mem = {0};
  mem.user_data  = alloc;
  mem.malloc     = tcp2_allocator_malloc;
  mem.free       = tcp2_allocator_free;
  mem.realloc    = tcp2_allocator_realloc;
  mem.calloc     = tcp2_allocator_calloc;
  return mem;
}

static void tcp2_set_callbacks(ngtcp2_callbacks* cb, bool client) {
  // Callback error: NGTCP2_ERR_CALLBACK_FAILURE

  if (client) {
    cb->client_initial = tcp2_client_initial;
    cb->recv_retry     = tcp2_recv_retry;
    // Optional
    cb->handshake_confirmed = tcp2_handshake_confirmed;
  } else {
    cb->recv_client_initial = tcp2_recv_client_initial;
  }

  cb->recv_crypto_data         = tcp2_recv_crypto_data;
  cb->encrypt                  = tcp2_encrypt;
  cb->decrypt                  = tcp2_decrypt;
  cb->hp_mask                  = tcp2_hp_mask;
  cb->rand                     = tcp2_rand;
  cb->get_new_connection_id    = tcp2_get_new_connection_id;
  cb->update_key               = tcp2_update_key;
  cb->delete_crypto_aead_ctx   = tcp2_delete_crypto_aead_ctx;
  cb->delete_crypto_cipher_ctx = tcp2_delete_crypto_cipher_ctx;
  cb->get_path_challenge_data  = tcp2_get_path_challenge_data;
  cb->version_negotiation      = tcp2_version_negotiation;

  // Optional
  cb->recv_stream_data         = tcp2_recv_stream_data;
  cb->recv_datagram            = tcp2_recv_datagram;
  cb->acked_stream_data_offset = tcp2_acked_stream_data_offset;
  cb->handshake_completed      = tcp2_handshake_completed;

  // ngtcp2_stream_open stream_open;
  // ngtcp2_stream_close stream_close;
  //
  // ngtcp2_remove_connection_id remove_connection_id;
  //
  // ngtcp2_stream_stop_sending stream_stop_sending;
  // ngtcp2_tls_early_data_rejected tls_early_data_rejected;
  //
  // ngtcp2_recv_version_negotiation recv_version_negotiation;
  // ngtcp2_recv_stateless_reset recv_stateless_reset;
  // ngtcp2_extend_max_streams extend_max_local_streams_bidi;
  // ngtcp2_extend_max_streams extend_max_local_streams_uni;
  // ngtcp2_path_validation path_validation;
  // ngtcp2_select_preferred_addr select_preferred_addr;
  // ngtcp2_stream_reset stream_reset;
  // ngtcp2_extend_max_streams extend_max_remote_streams_bidi;
  // ngtcp2_extend_max_streams extend_max_remote_streams_uni;
  // ngtcp2_extend_max_stream_data extend_max_stream_data;
  // ngtcp2_connection_id_status dcid_status;
  // ngtcp2_recv_new_token recv_new_token;
  // ngtcp2_ack_datagram ack_datagram;
  // ngtcp2_lost_datagram lost_datagram;
  // ngtcp2_recv_key recv_rx_key;
  // ngtcp2_recv_key recv_tx_key;
}

static int tcp2_outgoing_process(Tcp2Ctx* ctx, Bytes* pkt, u64 now, u64 bytes) {
  if (pkt->len != NGTCP2_MAX_UDP_PAYLOAD_SIZE)
    return -1;

  ngtcp2_ssize stream_write;
  Tcp2Msg*     msg      = 0;
  bool         pkt_full = false;
  u64          maxbytes = ngtcp2_conn_get_send_quantum(ctx->conn);

  while (!pkt_full && bytes < maxbytes && (msg = ctx->outgoing.head)) {
    LOG("!pkt_full, msg len=%d offset=%d", (int)msg->data.len,
        (int)msg->_offset);

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

          Tcp2MsgQ* sent = hashmap_val(&ctx->sent, it);
          if (s != HashmapStatus_Present)
            *sent = (Tcp2MsgQ){0};

          tcp2_msgq_enqueue(sent, done);
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
  LOG("pkt len=%d", (int)pkt->len);

  ngtcp2_conn_update_pkt_tx_time(ctx->conn, now);
  return 0;
}

static void tcp2_transport_params_default(ngtcp2_transport_params* params) {
  ngtcp2_transport_params_default(params);
  params->initial_max_streams_bidi            = 128;
  params->initial_max_streams_uni             = 128;
  params->initial_max_stream_data_bidi_local  = 128;
  params->initial_max_stream_data_bidi_remote = 128;
  params->initial_max_stream_data_uni         = 128;
  params->initial_max_data                    = 1 << 30;
  params->max_datagram_frame_size             = 1024;
}

static int tcp2_connect(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes* pkt,
                        const Tcp2ZeroRTT* zerortt, Allocator allocator,
                        u64 now) {
  LOG("");
  *ctx           = (Tcp2Ctx){0};
  ctx->allocator = allocator;
  if (Hashmap_i64_create(&ctx->sent, Tcp2MsgQ, allocator))
    return -1;

  ngtcp2_cid scid = {0};
  scid.datalen    = TCP2_CIDLEN;
  randombytes_buf(scid.data, scid.datalen);
  ngtcp2_cid dcid = {0};
  dcid.datalen    = TCP2_CIDLEN;
  randombytes_buf(dcid.data, dcid.datalen);
  ngtcp2_callbacks callbacks = {0};
  tcp2_set_callbacks(&callbacks, true);
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

  if (zerortt && zerortt->len) {
    LOG("setting 0rtt params");

    rc = ngtcp2_conn_decode_and_set_0rtt_transport_params(*client, zerortt->buf,
                                                          zerortt->len);
    if (rc != 0)
      return rc;

    if (zerortt->data.len) {
      LOG("enqueuing 0rtt data");
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

static int tcp2_accept(Tcp2Ctx* ctx, const ngtcp2_path* path, Bytes pkt,
                       Bytes* resp, Allocator allocator, u64 now) {
  LOG("");
  *ctx = (Tcp2Ctx){0};

  ctx->allocator = allocator;
  if (Hashmap_i64_create(&ctx->sent, Tcp2MsgQ, ctx->allocator))
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
  tcp2_set_callbacks(&callbacks, false);
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

  LOG("create server");
  ngtcp2_conn** server = &ctx->conn;
  rc = ngtcp2_conn_server_new(server, &hd.scid, &scid, path, hd.version,
                              &callbacks, &settings, &tparams, &ctx->mem, ctx);
  if (rc != 0)
    return rc;

  ctx->conn = *server;

  LOG("process packet");
  rc = ngtcp2_conn_read_pkt(*server, path, 0, pkt.buf, pkt.len,
                            settings.initial_ts);
  if (rc != 0) {
    ngtcp2_conn_del(*server);
    return rc;
  }

  LOG("send response");
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

static ngtcp2_addr tcp2_ipv4(const char* host, u16 port,
                             ngtcp2_sockaddr_union* addru) {
  ngtcp2_addr addr     = {&addru->sa, sizeof(addru->in)};
  addru->in.sin_family = AF_INET;
  addru->in.sin_port   = port;
  inet_pton(AF_INET, host, &addru->in.sin_addr);
  return addr;
}

static ngtcp2_addr tcp2_ipv6(const char* host, u16 port,
                             ngtcp2_sockaddr_union* addru) {
  ngtcp2_addr addr     = {&addru->sa, sizeof(addru->in6)};
  addru->in.sin_family = AF_INET6;
  addru->in.sin_port   = port;
  inet_pton(AF_INET6, host, &addru->in6.sin6_addr);
  return addr;
}

static void tcp2_conn_deinit(Tcp2Ctx* ctx) {
  ngtcp2_conn_del(ctx->conn);
  tcp2_outgoing_free(ctx);
  tcp2_sent_free(ctx);
  hashmap_deinit(&ctx->sent);
  *ctx = (Tcp2Ctx){0};
}

int demo_tcp2(int argc, char** argv) {
  // https://nghttp2.org/ngtcp2/programmers-guide.html
  LOG("tcp2");

  // ngtcp2_conn_get_send_quantum
  // ngtcp2_conn_get_expiry
  // NGTCP2_ERR_VERSION_NEGOTIATION, ngtcp2_pkt_write_version_negotiation
  // NGTCP2_ERR_IDLE_CLOSE, drop connection without calling write

  // 0rtt
  //   ngtcp2_conn_encode_0rtt_transport_params
  //   ngtcp2_conn_decode_and_set_0rtt_transport_params
  //   ngtcp2_conn_decode_and_set_remote_transport_params
  //   ngtcp2_conn_tls_early_data_rejected
  // Connection migration
  //   ngtcp2_conn_initiate_migration

  ngtcp2_sockaddr_union client_addru;
  ngtcp2_addr client_addr = tcp2_ipv4(TCP2_LOCALHOST, 2222, &client_addru);

  ngtcp2_sockaddr_union server_addru;
  ngtcp2_addr server_addr = tcp2_ipv6(TCP2_LOCALHOST6, 3333, &server_addru);

  Allocator alloc = allocatormi_allocator();

  u64 now = tcp2_current_time();

  // Client connect
  Bytes       pkt_connect;
  ngtcp2_path client_path = {.local = client_addr, .remote = server_addr};
  Tcp2Ctx     client_ctx;
  CHECK_TCP2(
      tcp2_connect(&client_ctx, &client_path, &pkt_connect, 0, alloc, now));

  // Server reply
  now                    = tcp2_current_time();
  Tcp2Ctx     server_ctx = {0};
  Bytes       pkt_connect_reply;
  ngtcp2_path server_path = {.local = server_addr, .remote = client_addr};
  LOG("receiving packet");
  CHECK_TCP2(tcp2_accept(&server_ctx, &server_path, pkt_connect,
                         &pkt_connect_reply, alloc, now));
  allocator_free(client_ctx.allocator, pkt_connect);

  // Client finish and send data
  now = tcp2_current_time();
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
  now = tcp2_current_time();
  Bytes msg2;
  CHECK0(
      allocator_u8(client_ctx.allocator, &msg2, NGTCP2_MAX_UDP_PAYLOAD_SIZE));
  LOG("server receiving msg");
  CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path, 0, msg.buf,
                                  msg.len, now));
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
  allocator_free(client_ctx.allocator, msg);

  LOG("client receiving packet");
  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0, msg2.buf,
                                  msg2.len, now));

  // Let's try a connection migration
  now = tcp2_current_time();
  ngtcp2_sockaddr_union client_addru_new;
  ngtcp2_addr           client_addr_new =
      tcp2_ipv4(TCP2_LOCALHOST, 2223, &client_addru_new);
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
      now = tcp2_current_time();
      CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0,
                                      msg2.buf, msg2.len, now));
      msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
    } else
      LOG("skip");

    if (msg2.len) {
      // Client recv
      now = tcp2_current_time();
      CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path_new, 0,
                                      msg2.buf, msg2.len, now));
      msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));
    } else
      LOG("skip");
  }

  now = tcp2_current_time();
  tcp2_outgoing_enqueue(&client_ctx, Str("hi2 from client"), stream);
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));

  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0,
                                  msg2.buf, msg2.len, now));
  now      = tcp2_current_time();
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));

  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path_new, 0,
                                  msg2.buf, msg2.len, now));

  // Copy out 0-RTT params
  Tcp2ZeroRTT zerortt = client_ctx.zerortt;

  // Close the connection
  now                = tcp2_current_time();
  msg2.len           = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  ngtcp2_ccerr ccerr = {0};
  ccerr.type         = NGTCP2_CCERR_TYPE_APPLICATION;
  ngtcp2_ssize sz    = ngtcp2_conn_write_connection_close(
      client_ctx.conn, &client_path_new, 0, msg2.buf, msg2.len, &ccerr, now);
  CHECK_TCP2(sz);
  msg2.len = sz;

  now = tcp2_current_time();
  CHECK(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0, msg2.buf,
                             msg2.len, now) == NGTCP2_ERR_DRAINING);

  // Cleanup

  allocator_free(client_ctx.allocator, msg2);

  tcp2_conn_deinit(&client_ctx);
  tcp2_conn_deinit(&server_ctx);

  // Attempt a 0-RTT data send
  LOG("0rtt send");
  now          = tcp2_current_time();
  zerortt.data = Str("zero!");
  CHECK_TCP2(tcp2_connect(&client_ctx, &client_path, &pkt_connect, &zerortt,
                          alloc, now));
  LOG("0rtt recv");
  now = tcp2_current_time();
  CHECK_TCP2(tcp2_accept(&server_ctx, &server_path, pkt_connect,
                         &pkt_connect_reply, alloc, now));
  LOG("0rtt reply");
  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0,
                                  pkt_connect_reply.buf, pkt_connect_reply.len,
                                  now));

  allocator_free(client_ctx.allocator, pkt_connect);
  allocator_free(server_ctx.allocator, pkt_connect_reply);

  tcp2_conn_deinit(&client_ctx);
  tcp2_conn_deinit(&server_ctx);

  return 0;
}
