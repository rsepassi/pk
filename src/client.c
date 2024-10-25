// stdlib
// ...

// vendor deps
#include "uv.h"
#include "minicoro.h"
#include "sodium.h"

// src
#include "log.h"
#include "stdtypes.h"

// Some constant data
char* A_to_B_message = "hello world";
char* A_seed_hex = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char* B_seed_hex = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

// CRYPTO
// ----------------------------------------------------------------------------

// A variant of X3DH where we use 32 0x30 bytes plus an ascii string
// identifying the application as initial input to the KDF
#define KDF_PREFIX "00000000000000000000000000000000pubsignal"

typedef struct { u8 bytes[32]; } B32;

typedef struct { u8 bytes[32]; } CryptoSeed;

typedef struct { u8 bytes[crypto_sign_SEEDBYTES]; } CryptoSignSeed;
typedef struct { u8 bytes[crypto_sign_PUBLICKEYBYTES]; } CryptoSignPK;
typedef struct {
  CryptoSignSeed seed;
  CryptoSignPK pk;
} CryptoSignSK;
typedef struct { u8 bytes[crypto_sign_BYTES]; } CryptoSig;

typedef struct { u8 bytes[crypto_kx_SEEDBYTES]; } CryptoKxSeed;
typedef struct { u8 bytes[crypto_kx_PUBLICKEYBYTES]; } CryptoKxPK;
typedef struct { u8 bytes[crypto_kx_SECRETKEYBYTES]; } CryptoKxSK;
typedef struct { u8 bytes[crypto_kx_SESSIONKEYBYTES]; } CryptoKxTx;

typedef struct {
  u8 mac[crypto_secretbox_MACBYTES];
  u8 nonce[crypto_secretbox_NONCEBYTES];
  Str encrypted;
} CryptoMessage;

u8 crypto_init() {
  STATIC_CHECK(sizeof(CryptoSeed) == sizeof(CryptoSignSeed));
  STATIC_CHECK(crypto_sign_SECRETKEYBYTES == sizeof(CryptoSignSK));

  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretbox_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretstream_xchacha20poly1305_KEYBYTES == sizeof(CryptoKxTx));

  return sodium_init();
}

static inline u8 u4_from_hex(char c, u8* out) {
  if (c >= '0' && c <= '9') {
    *out = c - '0';
    return 0;
  }
  if (c >= 'a' && c <= 'f') {
    *out = c - 'a' + 10;
    return 0;
  }
  if (c >= 'A' && c <= 'F') {
    *out = c - 'A' + 10;
    return 0;
  }
  return 1;
}

static inline u8 u8_from_hex(u8* s, u8* out) {
  u8 c0;
  u8 c1;
  if (u4_from_hex(s[0], &c0)) return 1;
  if (u4_from_hex(s[1], &c1)) return 1;

  *out = c0 * 16 + c1;
  return 0;
}

void bytes_from_hex(Str s, u8* out, u8 n) {
  CHECK(s.len == (n * 2));
  for (u8 i = 0; i < n; ++i) {
    CHECK(u8_from_hex(&s.buf[i * 2], &out[i]) == 0);
  }
}

// Printing
void phex(char* tag, u8* b, u64 len) {
  printf("%s=", tag);
  for (u8 i = 0; i < len; ++i) printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8*)&(k), sizeof(k))

typedef struct {
  CryptoSignPK sign;
  CryptoKxPK kx;
  CryptoSig kx_sig;
  CryptoKxPK kx_preshare;
  CryptoSig kx_preshare_sig;
} CryptoUserPState;

typedef struct {
  CryptoSignSK sign;
  CryptoKxSK kx;
  CryptoKxSK kx_preshare;
} CryptoUserSState;

typedef struct {
  CryptoUserPState pub;
  CryptoUserSState sec;
} CryptoUserState;

u8 crypto_seed_new_user(const CryptoSeed* seed, CryptoUserState* user) {
  // Identity key
  if (crypto_sign_seed_keypair((u8*)&user->pub.sign, (u8*)&user->sec.sign, (u8*)seed)) return 1;

  // sk = seed + pk
  DCHECK(sodium_memcmp((u8*)&user->sec.sign.seed, (u8*)seed, sizeof(CryptoSeed)) == 0);
  DCHECK(sodium_memcmp((u8*)&user->sec.sign.pk, (u8*)&user->pub.sign, sizeof(CryptoSignPK)) == 0);

  // Identity kx key
  if (crypto_kx_seed_keypair((u8*)&user->pub.kx, (u8*)&user->sec.kx, (u8*)seed)) return 1;

  // Pre-shared keypair
  if (crypto_kx_keypair((u8*)&user->pub.kx_preshare, (u8*)&user->sec.kx_preshare)) return 1;

  // Sign kx key
  if (crypto_sign_detached(
        (u8*)&user->pub.kx_sig, 0,  // signature
        (u8*)&user->pub.kx, sizeof(CryptoKxPK),  // input message
        (u8*)&user->sec.sign  // signing key
        )) return 1;

  // Sign pre-shared key
  if (crypto_sign_detached(
        (u8*)&user->pub.kx_preshare_sig, 0,  // signature
        (u8*)&user->pub.kx_preshare, sizeof(CryptoKxPK),  // input message
        (u8*)&user->sec.sign  // signing key
        )) return 1;

  return 0;
}

typedef struct {
  CryptoKxTx session_key;
  CryptoKxPK eph_key;
} CryptoX3DHInit;

typedef struct {
  CryptoSignPK sign;
  CryptoKxPK kx;
  CryptoSig kx_sig;
  CryptoKxPK kx_eph;
  CryptoKxPK kx_B;
  CryptoKxPK kx_prekey_B;
} CryptoX3DHFirstMessageHeaderAuth;

typedef struct {
  u8 header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  CryptoX3DHFirstMessageHeaderAuth auth;
  u64 ciphertxt_len;
} CryptoX3DHFirstMessageHeader;

// Alice -> Bob
u8 crypto_x3dh_initiate(const CryptoUserState* A, const CryptoUserPState* B, CryptoX3DHInit* out) {
  // Alice verifies Bob's kx key
  if (crypto_sign_verify_detached(
        (u8*)&B->kx_sig,
        (u8*)&B->kx, sizeof(CryptoKxPK),
        (u8*)&B->sign  // public key
        )) return 1;

  // Alice verifies Bob's pre-shared key
  if (crypto_sign_verify_detached(
        (u8*)&B->kx_preshare_sig,
        (u8*)&B->kx_preshare, sizeof(CryptoKxPK),
        (u8*)&B->sign  // public key
        )) return 1;

  // Alice ephemeral keypair
  CryptoKxSK A_eph_sk;
  if (crypto_kx_keypair((u8*)&out->eph_key, (u8*)&A_eph_sk)) return 1;

  CryptoKxTx dh1;  // DH1 = DH(IK_A, SPK_B)
  CryptoKxTx dh2;  // DH2 = DH(EK_A, IK_B)
  CryptoKxTx dh3;  // DH3 = DH(EK_A, SPK_B)
  if (crypto_kx_client_session_keys(0, (u8*)&dh1, (u8*)&A->pub.kx, (u8*)&A->sec.kx, (u8*)&B->kx_preshare)) return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh2, (u8*)&out->eph_key, (u8*)&A_eph_sk, (u8*)&B->kx)) return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh3, (u8*)&out->eph_key, (u8*)&A_eph_sk, (u8*)&B->kx_preshare)) return 1;

  // Alice computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3(+DH4, with a one-time prekey) provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0)) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)KDF_PREFIX, sizeof(KDF_PREFIX))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)&out->session_key)) return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&A_eph_sk, sizeof(CryptoKxSK));

  return 0;
}

// Bob <- Alice
u8 crypto_x3dh_reply(const CryptoUserState* B, const CryptoX3DHFirstMessageHeaderAuth* A, CryptoKxTx* out) {
  // Bob checks that the message is intended for him
  if (sodium_memcmp((u8*)&B->pub.kx, (u8*)&A->kx_B, sizeof(CryptoKxTx))) return 1;
  // Bob checks that the right prekey was used
  if (sodium_memcmp((u8*)&B->pub.kx_preshare, (u8*)&A->kx_prekey_B, sizeof(CryptoKxTx))) return 1;

  // Bob verifies Alices's kx key
  if (crypto_sign_verify_detached(
        (u8*)&A->kx_sig,
        (u8*)&A->kx, sizeof(CryptoKxPK),
        (u8*)&A->sign  // public key
        )) return 1;

  CryptoKxTx dh1;  // DH1 = DH(SPK_B, IK_A)
  CryptoKxTx dh2;  // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3;  // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8*)&dh1, (u8*)&B->pub.kx_preshare, (u8*)&B->sec.kx_preshare, (u8*)&A->kx)) return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh2, (u8*)&B->pub.kx, (u8*)&B->sec.kx, (u8*)&A->kx_eph)) return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh3, (u8*)&B->pub.kx_preshare, (u8*)&B->sec.kx_preshare, (u8*)&A->kx_eph)) return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3(+DH4, with a one-time prekey) provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0)) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)KDF_PREFIX, sizeof(KDF_PREFIX))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)out)) return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));

  return 0;
}


// ----------------------------------------------------------------------------

typedef struct {
  int argc;
  char** argv;
  uv_loop_t* loop;
} MainCoroCtx;

void main_coro(mco_coro* co) {
  MainCoroCtx* ctx = (MainCoroCtx*)mco_get_user_data(co);
  (void)ctx;

  // Alice seed
  Str A_seed_str = str_from_c(A_seed_hex);
  CHECK(A_seed_str.len == 64, "got length %" PRIu64, A_seed_str.len);
  CryptoSeed A_seed;
  bytes_from_hex(A_seed_str, A_seed.bytes, sizeof(A_seed));
  pcrypt(A_seed);

  // Bob seed
  Str B_seed_str = str_from_c(B_seed_hex);
  CHECK(B_seed_str.len == 64, "got length %" PRIu64, B_seed_str.len);
  CryptoSeed B_seed;
  bytes_from_hex(B_seed_str, B_seed.bytes, sizeof(B_seed));
  pcrypt(B_seed);

  // Alice init
  CryptoUserState A_sec;
  CHECK(crypto_seed_new_user(&A_seed, &A_sec) == 0);
  CryptoUserPState* A_pub = &A_sec.pub;

  // Bob init
  CryptoUserState B_sec;
  CHECK(crypto_seed_new_user(&B_seed, &B_sec) == 0);
  CryptoUserPState* B_pub = &B_sec.pub;

  // A -> B
  CryptoX3DHInit A_x3dh_init;
  CHECK(crypto_x3dh_initiate(&A_sec, B_pub, &A_x3dh_init) == 0);
  pcrypt(A_x3dh_init.session_key);

  // Alice's message to Bob
  Str A_msg_buf;
  {
    Str plaintxt = str_from_c(A_to_B_message);
    printf("plaintxt=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    u64 ciphertxt_len = plaintxt.len + crypto_secretstream_xchacha20poly1305_ABYTES;

    A_msg_buf.len = sizeof(CryptoX3DHFirstMessageHeader) + ciphertxt_len;
    A_msg_buf.buf = malloc(A_msg_buf.len);

    // Fill header
    CryptoX3DHFirstMessageHeader* header = (CryptoX3DHFirstMessageHeader*)A_msg_buf.buf;
    header->ciphertxt_len = ciphertxt_len;
    header->auth.sign = A_pub->sign;
    header->auth.kx = A_pub->kx;
    header->auth.kx_sig = A_pub->kx_sig;
    header->auth.kx_eph = A_x3dh_init.eph_key;
    header->auth.kx_B = B_pub->kx;
    header->auth.kx_prekey_B = B_pub->kx_preshare;

    u8* ciphertxt = A_msg_buf.buf + sizeof(CryptoX3DHFirstMessageHeader);

    crypto_secretstream_xchacha20poly1305_state state;
    CHECK(crypto_secretstream_xchacha20poly1305_init_push(&state, header->header, (u8*)&A_x3dh_init.session_key) == 0);
    CHECK(crypto_secretstream_xchacha20poly1305_push(
        &state,
        ciphertxt, NULL,
        plaintxt.buf, plaintxt.len,
        (u8*)&header->auth, sizeof(CryptoX3DHFirstMessageHeaderAuth),
        crypto_secretstream_xchacha20poly1305_TAG_FINAL) == 0);
  }

  // Bob receives Alice's message
  {
    // Parse the header + message
    CHECK(A_msg_buf.len >= sizeof(CryptoX3DHFirstMessageHeader));
    CryptoX3DHFirstMessageHeader* header = (CryptoX3DHFirstMessageHeader*)(A_msg_buf.buf);
    Str ciphertxt;
    ciphertxt.len = header->ciphertxt_len;
    ciphertxt.buf = A_msg_buf.buf + sizeof(CryptoX3DHFirstMessageHeader);
    CHECK(A_msg_buf.len == sizeof(CryptoX3DHFirstMessageHeader) + ciphertxt.len);
    CHECK(ciphertxt.len >= crypto_secretstream_xchacha20poly1305_ABYTES);

    CryptoKxTx B_x3dh_session_key;
    CHECK(crypto_x3dh_reply(&B_sec, &header->auth, &B_x3dh_session_key) == 0);
    pcrypt(B_x3dh_session_key);
    CHECK(sodium_memcmp((u8*)&A_x3dh_init.session_key, (u8*)&B_x3dh_session_key, sizeof(CryptoKxTx)) == 0);

    Str plaintxt;
    plaintxt.len = ciphertxt.len - crypto_secretstream_xchacha20poly1305_ABYTES;
    plaintxt.buf = malloc(plaintxt.len);

    crypto_secretstream_xchacha20poly1305_state state;
    CHECK(crypto_secretstream_xchacha20poly1305_init_pull(&state, header->header, (u8*)&B_x3dh_session_key) == 0);
    u8 tag;
    CHECK(crypto_secretstream_xchacha20poly1305_pull(&state, plaintxt.buf, 0, &tag, ciphertxt.buf, ciphertxt.len, (u8*)&header->auth, sizeof(CryptoX3DHFirstMessageHeaderAuth)) == 0);
    CHECK(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    printf("decrypted=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    free(plaintxt.buf);
  }

  free(A_msg_buf.buf);

  // TODO:
  // * Nonce needs to be incremented per session key or random
  // * Rotate pre-shared key
  // * One-time prekeys (and possibly other replay mitigations)
  // * Double ratchet

  // Lookup registrar for destination key from directory
  // DirectoryResult dir = pk_directory_lookup(ctx, pk)

  // Lookup mailbox for destination key from registrar
  // RecordResult rec = pk_registrar_record_lookup(ctx, dir.registrar, pk, RecordMailbox);

  // Package message for mailbox

  // Send message to mailbox

  // Cleanup
  // free(A_msg.encrypted.buf);
  // free(B_msg);
}

void* mco_alloc(size_t size, void* udata) {
  MainCoroCtx* ctx = (MainCoroCtx*)udata;
  (void)ctx;
  return calloc(1, size);
}

void mco_dealloc(void* ptr, size_t size, void* udata) {
  MainCoroCtx* ctx = (MainCoroCtx*)udata;
  (void)ctx;
  free(ptr);
}

int main(int argc, char** argv) {
  LOG("hello");

  CHECK(crypto_init() == 0);

  uv_loop_t loop;
  uv_loop_init(&loop);

  MainCoroCtx ctx = { argc, argv, &loop };
  mco_desc desc = mco_desc_init(main_coro, 1 << 21);  // 2MiB main stack
  desc.allocator_data = &ctx;
  desc.alloc_cb = mco_alloc;
  desc.dealloc_cb = mco_dealloc;
  desc.user_data = &ctx;
  mco_coro* co;
  mco_result res = mco_create(&co, &desc);
  CHECK(res == MCO_SUCCESS);
  res = mco_resume(co);
  CHECK(res == MCO_SUCCESS);

  uv_run(&loop, UV_RUN_DEFAULT);
  uv_loop_close(&loop);

  CHECK(mco_status(co) == MCO_DEAD);
  res = mco_destroy(co);
  CHECK(res == MCO_SUCCESS);

  LOG("goodbye");
  return 0;
}
