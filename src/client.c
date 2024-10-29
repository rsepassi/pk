// vendor deps
#include "argparse.h"
#include "minicoro.h"
#include "uv.h"
#include "lmdb.h"

// lib
#include "getpass.h"
#include "uvco.h"
#include "log.h"
#include "stdtypes.h"

// src
#include "crypto.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_PW_LEN 2048

// Global event loop
uv_loop_t* loop;

// Some constant data
char *A_to_B_message = "hello world";
char *A_seed_hex =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char *B_seed_hex =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

void bytes_from_hex(Str s, u8 *out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char *)s.buf, s.len, 0, 0, 0);
}

// Printing
void phex(char *tag, u8 *b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i)
    printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8 *)&(k), sizeof(k))

int demo_kv(int argc, const char **argv) {
  // get or put
  enum { KvGet, KvPut } cmd;
  MDB_val user_key;
  MDB_val user_val;
  {
    CHECK(argc >= 4, "usage: demo-kv kvfolder {get,put} key [value]");
    user_key.mv_data = (void*)argv[3];
    user_key.mv_size = strlen(user_key.mv_data);
    if (!strcmp(argv[2], "get")) {
      cmd = KvGet;
      CHECK(argc == 4);
    } else if (!strcmp(argv[2], "put")) {
      cmd = KvPut;
      CHECK(argc == 5);
      user_val.mv_data = (void*)argv[4];
      user_val.mv_size = strlen(user_val.mv_data);
    } else {
      CHECK(false, "must specify get or put");
    }
    (void)cmd;
  }

  // Open/create KV
  MDB_env* kv;
  MDB_dbi db;
  MDB_txn* txn;
  MDB_txn* rtxn;
  {
    const char* kv_path = argv[1];
    LOG("kv=%s", kv_path);

    // Check that directory exists
    uv_fs_t req;
    CHECK0(uvco_fs_stat(loop, &req, kv_path), "kv path must be a directory: %s", kv_path);
    CHECK(S_ISDIR(req.statbuf.st_mode), "kv path must be a directory: %s", kv_path);
    uv_fs_req_cleanup(&req);

    mode_t kv_mode = S_IRUSR | S_IWUSR | S_IRGRP; // rw-r-----
    CHECK0(mdb_env_create(&kv));
    CHECK0(mdb_env_open(kv, kv_path, MDB_NOLOCK, kv_mode));
    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_dbi_open(txn, 0, MDB_CREATE, &db));
    CHECK0(mdb_txn_commit(txn));
  }

  // Ask for password
  char* pw = malloc(MAX_PW_LEN);
  sodium_mlock(pw, MAX_PW_LEN);
  ssize_t pw_len;
  {
    fprintf(stderr, "pw > ");
    if (1) {
      pw_len = getpass(pw, MAX_PW_LEN);
      CHECK(pw_len >= 0);
    } else {
      pw = "asdfasdf";
      pw_len = strlen(pw);
    }
  }

  // If it's a fresh db:
  // * Store the password hash
  // * Generate a salt
  // Else:
  // * Validate the password
  // * Lookup the salt
  u8 salt[crypto_pwhash_SALTBYTES];
  {
    CHECK0(mdb_txn_begin(kv, 0, MDB_RDONLY, &rtxn));
    MDB_val salt_key = { 6, "__salthash" };
    MDB_val salt_val;
    int rc = mdb_get(rtxn, db, &salt_key, &salt_val);
    mdb_txn_reset(rtxn);
    if (rc == MDB_NOTFOUND) {
      LOG("fresh kv store");
      u8 pwhash_and_salt[crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES];

      // Create a random salt
      randombytes_buf(pwhash_and_salt, crypto_pwhash_SALTBYTES);
      memcpy(salt, pwhash_and_salt, crypto_pwhash_SALTBYTES);

      // Hash the password
      u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
      u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
      CHECK0(crypto_pwhash_str((char*)(pwhash_and_salt + crypto_pwhash_SALTBYTES), pw, pw_len, opslimit, memlimit));

      // Insert in kv
      salt_val.mv_size = crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES;
      salt_val.mv_data = pwhash_and_salt;
      CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
      CHECK0(mdb_put(txn, db, &salt_key, &salt_val, 0));
      CHECK0(mdb_txn_commit(txn));
    } else {
      CHECK0(rc, "failed to read database");
      CHECK(salt_val.mv_size == crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES);

      // Copy out salt
      memcpy(salt, salt_val.mv_data, crypto_pwhash_SALTBYTES);

      // Verify password hash
      CHECK0(crypto_pwhash_str_verify((char*)(salt_val.mv_data + crypto_pwhash_SALTBYTES), pw, pw_len), "wrong password");
    }
  }

  // Derive the key
  u8 key[crypto_secretbox_KEYBYTES];
  {
    u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    CHECK0(crypto_pwhash(key, sizeof(key), pw, pw_len, salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13));
  }

  // Password no longer needed
  sodium_munlock(pw, MAX_PW_LEN);
  free(pw);

  // Encrypt the key with a nonce derived from the key and db salt
  u64 ekey_len = user_key.mv_size + crypto_secretbox_MACBYTES;
  u8* ekey = malloc(ekey_len);
  {
    u8 key_nonce[crypto_secretbox_NONCEBYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, 0, 0, sizeof(key_nonce));
    crypto_generichash_update(&state, user_key.mv_data, user_key.mv_size);
    crypto_generichash_update(&state, salt, sizeof(salt));
    crypto_generichash_final(&state, key_nonce, sizeof(key_nonce));
    CHECK0(crypto_secretbox_easy(ekey, user_key.mv_data, user_key.mv_size, key_nonce, key));
    user_key.mv_data = ekey;
    user_key.mv_size = ekey_len;
  }

  if (cmd == KvGet) {
    CHECK0(mdb_txn_begin(kv, 0, MDB_RDONLY, &rtxn));
    int rc = mdb_get(rtxn, db, &user_key, &user_val);
    if (rc == MDB_NOTFOUND) {
      LOG("key not found");
      return 1;
    } else {
      CHECK0(rc, "failed to read database");
      u64 decrypted_len = user_val.mv_size - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
      u8* decrypted = malloc(decrypted_len);
      CHECK0(crypto_secretbox_open_easy(
            decrypted,
            user_val.mv_data + crypto_secretbox_NONCEBYTES,
            user_val.mv_size - crypto_secretbox_NONCEBYTES,
            user_val.mv_data,
            key), "failed to decrypt");
      printf("%.*s\n", (int)decrypted_len, decrypted);
      free(decrypted);
    }
  } else if (cmd == KvPut) {
    u64 encrypted_len = user_val.mv_size + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
    u8* encrypted = malloc(encrypted_len);
    randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
    CHECK0(crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, user_val.mv_data, user_val.mv_size, encrypted, key));
    user_val.mv_data = encrypted;
    user_val.mv_size = encrypted_len;

    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_put(txn, db, &user_key, &user_val, 0));
    CHECK0(mdb_txn_commit(txn));

    free(encrypted);
  } else CHECK(false);

  free(ekey);
  mdb_env_close(kv);
  return 0;
}

int demo_x3dh(int argc, const char **argv) {
  // Alice seed
  Str A_seed_str = str_from_c(A_seed_hex);
  CHECK(A_seed_str.len == 64, "got length %d", (int)A_seed_str.len);
  CryptoSeed A_seed;
  sodium_hex2bin((u8 *)&A_seed, sizeof(A_seed), (char *)A_seed_str.buf,
                 A_seed_str.len, 0, 0, 0);
  pcrypt(A_seed);

  // Bob seed
  Str B_seed_str = str_from_c(B_seed_hex);
  CHECK(B_seed_str.len == 64, "got length %d", (int)B_seed_str.len);
  CryptoSeed B_seed;
  sodium_hex2bin((u8 *)&B_seed, sizeof(B_seed), (char *)B_seed_str.buf,
                 B_seed_str.len, 0, 0, 0);
  pcrypt(B_seed);

  // Alice init
  CryptoUserState A_sec;
  CHECK(crypto_seed_new_user(&A_seed, &A_sec) == 0);

  // Bob init
  CryptoUserState B_sec;
  CHECK(crypto_seed_new_user(&B_seed, &B_sec) == 0);

  // Alice's message to Bob
  Str A_msg_buf;
  {
    Str plaintxt = str_from_c(A_to_B_message);
    printf("plaintxt=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    A_msg_buf.len = crypto_x3dh_first_msg_len(plaintxt.len);
    A_msg_buf.buf = malloc(A_msg_buf.len);
    CHECK(crypto_x3dh_first_msg(&A_sec, &B_sec.pub, plaintxt, &A_msg_buf) == 0);
  }

  phex("msg", A_msg_buf.buf, A_msg_buf.len);

  // Bob receives Alice's message
  {
    Str ciphertxt;
    CryptoX3DHFirstMessageHeader *header;
    CHECK(crypto_x3dh_first_msg_parse(A_msg_buf, &header, &ciphertxt) == 0);

    Str plaintxt;
    plaintxt.len = crypto_plaintxt_len(ciphertxt.len);
    plaintxt.buf = malloc(plaintxt.len);

    CHECK(crypto_x3dh_first_msg_recv(&B_sec, header, ciphertxt, &plaintxt) ==
          0);

    printf("decrypted=%.*s\n", (int)plaintxt.len, plaintxt.buf);
    CHECK(plaintxt.len == strlen(A_to_B_message));
    CHECK(sodium_memcmp(plaintxt.buf, A_to_B_message, strlen(A_to_B_message)) ==
          0);

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
  // RecordResult rec = pk_registrar_record_lookup(ctx, dir.registrar, pk,
  // RecordMailbox);

  // Package message for mailbox

  // Send message to mailbox
  return 0;
}

static const char *const usages[] = {
    "pk [options] [cmd] [args]\n\n    Commands:"
    "\n      - demo-x3dh"
    "\n      - demo-kv"
    ,
    NULL,
};

struct cmd_struct {
  const char *cmd;
  int (*fn)(int, const char **);
};

static struct cmd_struct commands[] = {
    {"demo-x3dh", demo_x3dh},
    {"demo-kv", demo_kv},
};

typedef struct {
  int argc;
  const char **argv;
} MainCoroCtx;

void coro_exit(u8 code) {
  mco_push(mco_running(), &code, 1);
}

void main_coro(mco_coro *co) {
  MainCoroCtx *ctx = (MainCoroCtx *)mco_get_user_data(co);

  int argc = ctx->argc;
  const char **argv = ctx->argv;

  struct argparse argparse;
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_END(),
  };
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  if (argc < 1) {
    argparse_usage(&argparse);
    return coro_exit(1);
  }

  struct cmd_struct *cmd = NULL;
  for (int i = 0; i < ARRAY_SIZE(commands); i++) {
    if (!strcmp(commands[i].cmd, argv[0])) {
      cmd = &commands[i];
      break;
    }
  }

  if (!cmd) {
    argparse_usage(&argparse);
    return coro_exit(1);
  }

  return coro_exit(cmd->fn(argc, argv));
}

#define MAIN_STACK_SIZE 1 << 21

void* mco_alloc(size_t size, void *udata) {
  MainCoroCtx *ctx = (MainCoroCtx *)udata;
  (void)ctx;
  (void)size;
  return calloc(1, size);
}

void mco_dealloc(void *ptr, size_t size, void *udata) {
  MainCoroCtx *ctx = (MainCoroCtx *)udata;
  (void)ctx;
  (void)size;
  return free(ptr);
}

int main(int argc, const char **argv) {
  LOG("hello");

  // libsodium init
  CHECK(crypto_init() == 0);

  // libuv init
  loop = malloc(sizeof(uv_loop_t));
  CHECK(loop);
  uv_loop_init(loop);

  // coro init
  MainCoroCtx ctx = {argc, argv};
  mco_desc desc = mco_desc_init(main_coro, MAIN_STACK_SIZE);
  desc.allocator_data = &ctx;
  desc.alloc_cb = mco_alloc;
  desc.dealloc_cb = mco_dealloc;
  desc.user_data = &ctx;
  mco_coro *co;
  CHECK(mco_create(&co, &desc) == MCO_SUCCESS);

  // run
  CHECK(mco_resume(co) == MCO_SUCCESS);
  if (mco_status(co) == MCO_SUSPENDED)
    uv_run(loop, UV_RUN_DEFAULT);

  u8 rc = 0;
  if (mco_get_storage_size(co) > 0) mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  uv_loop_close(loop);
  free(loop);

  LOG("goodbye (code=%d)", rc);
  return rc;
}
