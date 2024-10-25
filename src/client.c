// vendor deps
#include "uv.h"
#include "minicoro.h"

// src
#include "log.h"
#include "stdtypes.h"
#include "crypto.h"

// Some constant data
char* A_to_B_message = "hello world";
char* A_seed_hex = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char* B_seed_hex = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

void bytes_from_hex(Str s, u8* out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char*)s.buf, s.len, 0, 0, 0);
}

// Printing
void phex(char* tag, u8* b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i) printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8*)&(k), sizeof(k))

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
  sodium_hex2bin((u8*)&A_seed, sizeof(A_seed), (char*)A_seed_str.buf, A_seed_str.len, 0, 0, 0);
  pcrypt(A_seed);

  // Bob seed
  Str B_seed_str = str_from_c(B_seed_hex);
  CHECK(B_seed_str.len == 64, "got length %" PRIu64, B_seed_str.len);
  CryptoSeed B_seed;
  sodium_hex2bin((u8*)&B_seed, sizeof(B_seed), (char*)B_seed_str.buf, B_seed_str.len, 0, 0, 0);
  pcrypt(B_seed);

  // Alice init
  CryptoUserState A_sec;
  CHECK(crypto_seed_new_user(&A_seed, &A_sec) == 0);

  // Bob init
  CryptoUserState B_sec;
  CHECK(crypto_seed_new_user(&B_seed, &B_sec) == 0);
  CryptoUserPState* B_pub = &B_sec.pub;

  // Alice's message to Bob
  Str A_msg_buf;
  {
    Str plaintxt = str_from_c(A_to_B_message);
    printf("plaintxt=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    A_msg_buf.len = crypto_x3dh_first_msg_len(plaintxt.len);
    A_msg_buf.buf = malloc(A_msg_buf.len);
    CHECK(crypto_x3dh_first_msg(&A_sec, B_pub, plaintxt, &A_msg_buf) == 0);
  }

  phex("msg", A_msg_buf.buf, A_msg_buf.len);

  // Bob receives Alice's message
  {
    Str ciphertxt;
    CryptoX3DHFirstMessageHeader* header;
    CHECK(crypto_x3dh_first_msg_parse(A_msg_buf, &header, &ciphertxt) == 0);

    Str plaintxt;
    plaintxt.len = crypto_plaintxt_len(ciphertxt.len);
    plaintxt.buf = malloc(plaintxt.len);

    CHECK(crypto_x3dh_first_msg_recv(&B_sec, header, ciphertxt, &plaintxt) == 0);

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
