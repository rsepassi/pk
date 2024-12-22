#include "ngtcp2/ngtcp2.h"
#include "sodium.h"
#include "stdtypes.h"
#include "tcp2.h"

#define TCP2_AEAD_OVERHEAD crypto_aead_chacha20poly1305_IETF_ABYTES  // 16

typedef struct {
  u8                       secret[1];
  u8                       iv[8];
  ngtcp2_crypto_aead_ctx   aead;
  ngtcp2_crypto_cipher_ctx cipher;
  ngtcp2_crypto_ctx        ctx;
} Tcp2Key;

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
          memcpy(ctx->zerortt.params_buf, &data[i + 1], data[i]);
          ctx->zerortt.params_len = data[i];
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
  LOG("");
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

void tcp2_set_crypto_callbacks(ngtcp2_callbacks* cb, bool client) {
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
  cb->update_key               = tcp2_update_key;
  cb->delete_crypto_aead_ctx   = tcp2_delete_crypto_aead_ctx;
  cb->delete_crypto_cipher_ctx = tcp2_delete_crypto_cipher_ctx;
  cb->version_negotiation      = tcp2_version_negotiation;
  cb->handshake_completed      = tcp2_handshake_completed;
}
