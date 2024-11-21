#include "sodium.h"
#include "tls_api.h"

#include <string.h>

typedef struct {
  picoquic_cnx_t* cnx;
} picoquic_noise_ctx_t;

typedef struct {
  uint8_t key[64];
} noise_ctx_t;

static uint64_t public_random_seed[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                          9, 10, 11, 12, 13, 14, 15, 16};
static int public_random_index = 0;
static const uint64_t public_random_multiplier = 1181783497276652981ull;
static uint64_t public_random_obfuscator = 0x5555555555555555ull;

int picoquic_set_cipher_suite(picoquic_quic_t* quic, int cipher_suite_id) {
  if (cipher_suite_id != PICOQUIC_CHACHA20_POLY1305_SHA256)
    return -1;
  return 0;
}

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len) {
  randombytes_buf(buf, len);
}

uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic,
                                        uint64_t rnd_max) {
  uint64_t rnd;
  uint64_t rnd_min = UINT64_MAX % rnd_max;

  do {
    rnd = picoquic_public_random_64();
  } while (rnd < rnd_min);

  return rnd % rnd_max;
}

uint64_t picoquic_public_uniform_random(uint64_t rnd_max) {
  return picoquic_crypto_uniform_random(0, rnd_max);
}

void picoquic_public_random(void* buf, size_t len) {
  picoquic_crypto_random(0, buf, len);
}

void picoquic_public_random_seed(picoquic_quic_t* quic) {
  uint64_t seed[3];
  picoquic_crypto_random(quic, &seed, sizeof(seed));

  picoquic_public_random_seed_64(seed[0], 0);
  public_random_obfuscator = seed[1];
}

static uint64_t picoquic_public_random_step(void) {
  uint64_t s1;
  const uint64_t s0 = public_random_seed[public_random_index++];
  public_random_index &= 15;
  s1 = public_random_seed[public_random_index];
  s1 ^= (s1 << 31);         // a
  s1 ^= (s1 >> 11);         // b
  s1 ^= (s0 ^ (s0 >> 30));  // c
  public_random_seed[public_random_index] = s1;
  return s1;
}

uint64_t picoquic_public_random_64(void) {
  uint64_t s1 = picoquic_public_random_step();
  s1 *= public_random_multiplier;
  s1 ^= public_random_obfuscator;
  return s1;
}

void picoquic_public_random_seed_64(uint64_t seed, int reset) {
  if (reset) {
    public_random_index = 0;
    for (uint64_t i = 0; i < 16; i++) {
      public_random_seed[i] = i + 1u;
    }
    public_random_obfuscator = 0x5555555555555555ull;
  }

  public_random_seed[public_random_index] ^= seed;

  for (int i = 0; i < 16; i++) {
    (void)picoquic_public_random_step();
  }
}

void picoquic_tls_set_verify_certificate_callback(
    picoquic_quic_t* quic, struct st_ptls_verify_certificate_t* cb,
    picoquic_free_verify_certificate_ctx free_fn) {
  abort();
}

void picoquic_dispose_verify_certificate_callback(picoquic_quic_t* quic) {}

void picoquic_tls_set_client_authentication(picoquic_quic_t* quic,
                                            int client_authentication) {
  if (client_authentication <= 0)
    abort();
}

int picoquic_tls_client_authentication_activated(picoquic_quic_t* quic) {
  return 1;
}

int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx,
                               uint64_t current_time) {
  picoquic_noise_ctx_t* ctx = calloc(1, sizeof(picoquic_noise_ctx_t));
  if (ctx == NULL)
    return -1;

  ctx->cnx = cnx;
  cnx->tls_ctx = (void*)ctx;
  return 0;
}

void picoquic_tlscontext_free(void* ctx) { free(ctx); }

int picoquic_master_tlscontext(picoquic_quic_t* quic,
                               char const* cert_file_name,
                               char const* key_file_name,
                               char const* cert_root_file_name,
                               const uint8_t* ticket_key,
                               size_t ticket_key_length) {
  if (sodium_init())
    return -1;

  uint8_t key[64];
  FILE* f = fopen(key_file_name, "rb");
  if (f == NULL)
    return -1;
  size_t nread = fread(key, sizeof(key), 1, f);
  fclose(f);
  if (nread != sizeof(key))
    return -1;

  noise_ctx_t* ctx = calloc(1, sizeof(noise_ctx_t));
  if (ctx == NULL)
    return -1;
  memcpy(ctx->key, key, sizeof(key));
  sodium_memzero(key, sizeof(key));

  quic->tls_master_ctx = ctx;
  return 0;
}

void picoquic_master_tlscontext_free(picoquic_quic_t* quic) {
  noise_ctx_t* ctx = quic->tls_master_ctx;
  sodium_memzero((void*)ctx, sizeof(noise_ctx_t));
  free(ctx);
}

// TODO: Implement
// picoquic_aead_confidentiality_limit
// picoquic_aead_decrypt_generic
// picoquic_aead_decrypt_mp
// picoquic_aead_encrypt_generic
// picoquic_aead_encrypt_mp
// picoquic_aead_free
// picoquic_aead_get_checksum_length
// picoquic_aead_integrity_limit
// picoquic_apply_rotated_keys
// picoquic_cipher_free
// picoquic_compute_new_rotated_keys
// picoquic_create_cnxid_reset_secret
// picoquic_crypto_context_free
// picoquic_delete_retry_protection_contexts
// picoquic_encode_retry_protection
// picoquic_find_retry_protection_context
// picoquic_get_initial_aead_context
// picoquic_get_tls_time
// picoquic_initialize_tls_stream
// picoquic_is_tls_complete
// picoquic_pn_encrypt
// picoquic_pn_iv_size
// picoquic_prepare_retry_token
// picoquic_setup_initial_traffic_keys
// picoquic_tls_stream_process
// picoquic_tlscontext_trim_after_handshake
// picoquic_verify_retry_protection
// picoquic_verify_retry_token

void picoquic_tlscontext_trim_after_handshake(picoquic_cnx_t* cnx);

int picoquic_tls_stream_process(picoquic_cnx_t* cnx, int* data_consumed,
                                uint64_t current_time);
int picoquic_is_tls_complete(picoquic_cnx_t* cnx);

int picoquic_initialize_tls_stream(picoquic_cnx_t* cnx, uint64_t current_time);

uint64_t picoquic_get_tls_time(picoquic_quic_t* quic);

size_t picoquic_aead_get_checksum_length(void* aead_context);

size_t picoquic_aead_encrypt_generic(uint8_t* output, const uint8_t* input,
                                     size_t input_length, uint64_t seq_num,
                                     const uint8_t* auth_data,
                                     size_t auth_data_length,
                                     void* aead_context);
size_t picoquic_aead_decrypt_generic(uint8_t* output, const uint8_t* input,
                                     size_t input_length, uint64_t seq_num,
                                     const uint8_t* auth_data,
                                     size_t auth_data_length, void* aead_ctx);

size_t picoquic_aead_decrypt_mp(uint8_t* output, const uint8_t* input,
                                size_t input_length, uint64_t path_id,
                                uint64_t seq_num, const uint8_t* auth_data,
                                size_t auth_data_length, void* aead_context);
size_t picoquic_aead_encrypt_mp(uint8_t* output, const uint8_t* input,
                                size_t input_length, uint64_t path_id,
                                uint64_t seq_num, const uint8_t* auth_data,
                                size_t auth_data_length, void* aead_context);

uint64_t picoquic_aead_integrity_limit(void* aead_ctx);
uint64_t picoquic_aead_confidentiality_limit(void* aead_ctx);

void picoquic_aead_free(void* aead_context);
void picoquic_cipher_free(void* cipher_context);

size_t picoquic_pn_iv_size(void* pn_enc);

void picoquic_pn_encrypt(void* pn_enc, const void* iv, void* output,
                         const void* input, size_t len);

int picoquic_setup_initial_traffic_keys(picoquic_cnx_t* cnx);

int picoquic_get_initial_aead_context(picoquic_quic_t* quic, int version_index,
                                      picoquic_connection_id_t* initial_cnxid,
                                      int is_client, int is_enc,
                                      void** aead_ctx, void** pn_enc_ctx);

int picoquic_compute_new_rotated_keys(picoquic_cnx_t* cnx);
void picoquic_apply_rotated_keys(picoquic_cnx_t* cnx, int is_enc);

void picoquic_crypto_context_free(picoquic_crypto_context_t* ctx);

int picoquic_create_cnxid_reset_secret(
    picoquic_quic_t* quic, picoquic_connection_id_t* cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE]);

int picoquic_prepare_retry_token(picoquic_quic_t* quic,
                                 const struct sockaddr* addr_peer,
                                 uint64_t current_time,
                                 const picoquic_connection_id_t* odcid,
                                 const picoquic_connection_id_t* rcid,
                                 uint32_t initial_pn, uint8_t* token,
                                 size_t token_max, size_t* token_size);

int picoquic_verify_retry_token(picoquic_quic_t* quic,
                                const struct sockaddr* addr_peer,
                                uint64_t current_time, int* is_new_token,
                                picoquic_connection_id_t* odcid,
                                const picoquic_connection_id_t* rcid,
                                uint32_t initial_pn, const uint8_t* token,
                                size_t token_size, int check_reuse);

void* picoquic_find_retry_protection_context(picoquic_quic_t* quic,
                                             int version_index, int sending);
void picoquic_delete_retry_protection_contexts(picoquic_quic_t* quic);
size_t picoquic_encode_retry_protection(void* integrity_aead, uint8_t* bytes,
                                        size_t bytes_max, size_t byte_index,
                                        const picoquic_connection_id_t* odcid);
int picoquic_verify_retry_protection(void* integrity_aead, uint8_t* bytes,
                                     size_t* length, size_t byte_index,
                                     const picoquic_connection_id_t* odcid);
