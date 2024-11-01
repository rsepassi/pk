// src
#include "nik.h"
#include "crypto.h"

// vendor deps
#include "argparse.h"
#include "libbase58.h"
#include "lmdb.h"
#include "minicoro.h"
#include "taia.h"
#include "uv.h"

// lib
#include "getpass.h"
#include "log.h"
#include "stdtypes.h"
#include "uvco.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_PW_LEN 2048

// Global event loop
uv_loop_t *loop;

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

int nik_keys_kx_from_seed(const CryptoSeed *seed, CryptoKxKeypair *out) {
  CryptoSignPK pk;
  CryptoSignSK sk;
  if (crypto_sign_seed_keypair((u8 *)&pk, (u8 *)&sk, (u8 *)seed))
    return 1;

  if (crypto_sign_ed25519_pk_to_curve25519((u8 *)&out->pk, (u8 *)&pk))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8 *)&out->sk, (u8 *)&sk))
    return 1;
  return 0;
}

int demo_nik(int argc, const char **argv) {
  CryptoKxKeypair kx_keys_i;
  {
    Str A_seed_str = str_from_c(A_seed_hex);
    CryptoSeed A_seed;
    sodium_hex2bin((u8 *)&A_seed, sizeof(A_seed), (char *)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &kx_keys_i));
  }

  CryptoKxKeypair kx_keys_r;
  {
    Str B_seed_str = str_from_c(B_seed_hex);
    CryptoSeed B_seed;
    sodium_hex2bin((u8 *)&B_seed, sizeof(B_seed), (char *)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &kx_keys_r));
  }

  NIK_Keys keys_i = {&kx_keys_i.pk, &kx_keys_i.sk};
  NIK_Keys keys_r = {&kx_keys_r.pk, &kx_keys_r.sk};

  // I
  LOG("i2r");
  NIK_HandshakeState state_i;
  NIK_HandshakeKeys hkeys_i = {&keys_i, keys_r.pk};
  NIK_HandshakeMsg1 msg1;
  CHECK0(nik_handshake_init(hkeys_i, &state_i, &msg1));
  phex("IC", state_i.chaining_key, NIK_CHAIN_SZ);

  // R
  LOG("i2r check");
  NIK_HandshakeState state_r;
  NIK_HandshakeKeys hkeys_r = {&keys_r, keys_i.pk};
  CHECK0(nik_handshake_init_check(hkeys_r, &msg1, &state_r));
  phex("RC", state_r.chaining_key, NIK_CHAIN_SZ);

  // R
  LOG("r2i");
  NIK_HandshakeMsg2 msg2;
  CHECK0(nik_handshake_respond(hkeys_r, &msg1, &state_r, &msg2));
  phex("RC", state_r.chaining_key, NIK_CHAIN_SZ);

  // I
  LOG("r2i check");
  CHECK0(nik_handshake_respond_check(hkeys_i, &msg2, &state_i));
  phex("IC", state_i.chaining_key, NIK_CHAIN_SZ);

  // I
  LOG("i derive");
  NIK_TxState tx_i;
  CHECK0(nik_handshake_final(&state_i, &tx_i, true));

  // R
  LOG("r derive");
  NIK_TxState tx_r;
  CHECK0(nik_handshake_final(&state_r, &tx_r, false));

  // Check that I and R have the same transfer keys
  phex("tx", (u8 *)&tx_i, sizeof(tx_i));
  CHECK0(sodium_memcmp(&tx_i.send, &tx_r.recv, sizeof(tx_i.send)));
  CHECK0(sodium_memcmp(&tx_i.recv, &tx_r.send, sizeof(tx_i.send)));
  CHECK(tx_i.send_n == 0);
  CHECK(tx_i.recv_n == 0);
  CHECK(tx_r.send_n == 0);
  CHECK(tx_r.recv_n == 0);
  CHECK(tx_r.recv_max_counter == 0);
  CHECK(tx_i.sender == tx_r.receiver);
  CHECK(tx_i.receiver == tx_r.sender);

  // I: Send a message
  Str payload = str_from_c("hello!");
  Str send_msg;
  {
    LOG("send: %.*s", (int)payload.len, payload.buf);
    u64 send_sz = nik_sendmsg_sz(payload.len);
    send_msg = (Str){.len = send_sz, .buf = malloc(send_sz)};
    CHECK(send_msg.buf);
    CHECK0(nik_msg_send(&tx_i, payload, send_msg));
  }

  // R: Receive a message
  {
    CHECK0(nik_msg_recv(&tx_r, &send_msg));
    LOG("recv: %.*s", (int)send_msg.len, send_msg.buf);
    CHECK(str_eq(payload, send_msg));
  }
  free(send_msg.buf);

  // I: Send another
  payload = str_from_c("ahoy!");
  {
    LOG("send: %.*s", (int)payload.len, payload.buf);
    u64 send_sz = nik_sendmsg_sz(payload.len);
    send_msg = (Str){.len = send_sz, .buf = malloc(send_sz)};
    CHECK0(nik_msg_send(&tx_i, payload, send_msg));
  }

  // R: Receive another
  {
    CHECK0(nik_msg_recv(&tx_r, &send_msg));
    LOG("recv: %.*s", (int)send_msg.len, send_msg.buf);
    CHECK(str_eq(payload, send_msg));
  }

  CHECK(tx_i.send_n == 2);
  CHECK(tx_i.recv_n == 0);
  CHECK(tx_r.send_n == 0);
  CHECK(tx_r.recv_n == 2);
  CHECK(tx_r.recv_max_counter == 1);

  return 0;
}

int demo_kv(int argc, const char **argv) {
  // get or put
  enum { KvGet, KvPut } cmd;
  MDB_val user_key;
  MDB_val user_val;
  {
    CHECK(argc >= 4, "usage: demo-kv kvfolder {get,put} key [value]");
    user_key.mv_data = (void *)argv[3];
    user_key.mv_size = strlen(user_key.mv_data);
    if (!strcmp(argv[2], "get")) {
      cmd = KvGet;
      CHECK(argc == 4);
    } else if (!strcmp(argv[2], "put")) {
      cmd = KvPut;
      CHECK(argc == 5);
      user_val.mv_data = (void *)argv[4];
      user_val.mv_size = strlen(user_val.mv_data);
    } else {
      CHECK(false, "must specify get or put");
    }
    (void)cmd;
  }

  // Open/create KV
  MDB_env *kv;
  MDB_dbi db;
  MDB_txn *txn;
  MDB_txn *rtxn;
  {
    const char *kv_path = argv[1];
    LOG("kv=%s", kv_path);

    // Check that directory exists
    uv_fs_t req;
    CHECK0(uvco_fs_stat(loop, &req, kv_path), "kv path must be a directory: %s",
           kv_path);
    CHECK(S_ISDIR(req.statbuf.st_mode), "kv path must be a directory: %s",
          kv_path);
    uv_fs_req_cleanup(&req);

    mode_t kv_mode = S_IRUSR | S_IWUSR | S_IRGRP; // rw-r-----
    CHECK0(mdb_env_create(&kv));
    CHECK0(mdb_env_open(kv, kv_path, MDB_NOLOCK, kv_mode));
    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_dbi_open(txn, 0, MDB_CREATE, &db));
    CHECK0(mdb_txn_commit(txn));
  }

  // Ask for password
  char *pw = malloc(MAX_PW_LEN);
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
    char* salt_str = "__salthash";
    MDB_val salt_key = {strlen(salt_str), salt_str};
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
      CHECK0(
          crypto_pwhash_str((char *)(pwhash_and_salt + crypto_pwhash_SALTBYTES),
                            pw, pw_len, opslimit, memlimit));

      // Insert in kv
      salt_val.mv_size = crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES;
      salt_val.mv_data = pwhash_and_salt;
      CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
      CHECK0(mdb_put(txn, db, &salt_key, &salt_val, 0));
      CHECK0(mdb_txn_commit(txn));
    } else {
      CHECK0(rc, "failed to read database");
      CHECK(salt_val.mv_size ==
            crypto_pwhash_SALTBYTES + crypto_pwhash_STRBYTES);

      // Copy out salt
      memcpy(salt, salt_val.mv_data, crypto_pwhash_SALTBYTES);

      // Verify password hash
      CHECK0(
          crypto_pwhash_str_verify(
              (char *)(salt_val.mv_data + crypto_pwhash_SALTBYTES), pw, pw_len),
          "wrong password");
    }
  }

  // Derive the key
  u8 key[crypto_secretbox_KEYBYTES];
  {
    u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    CHECK0(crypto_pwhash(key, sizeof(key), pw, pw_len, salt, opslimit, memlimit,
                         crypto_pwhash_ALG_ARGON2ID13));
  }

  // Password no longer needed
  sodium_munlock(pw, MAX_PW_LEN);
  free(pw);

  // Encrypt the key with a nonce derived from the key and db salt
  u64 ekey_len = user_key.mv_size + crypto_secretbox_MACBYTES;
  u8 *ekey = malloc(ekey_len);
  {
    u8 key_nonce[crypto_secretbox_NONCEBYTES];
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, 0, 0, sizeof(key_nonce));
    crypto_generichash_blake2b_update(&state, user_key.mv_data,
                                      user_key.mv_size);
    crypto_generichash_blake2b_update(&state, salt, sizeof(salt));
    crypto_generichash_blake2b_final(&state, key_nonce, sizeof(key_nonce));
    CHECK0(crypto_secretbox_easy(ekey, user_key.mv_data, user_key.mv_size,
                                 key_nonce, key));
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
      u64 decrypted_len = user_val.mv_size - crypto_secretbox_NONCEBYTES -
                          crypto_secretbox_MACBYTES;
      u8 *decrypted = malloc(decrypted_len);
      CHECK0(crypto_secretbox_open_easy(
                 decrypted, user_val.mv_data + crypto_secretbox_NONCEBYTES,
                 user_val.mv_size - crypto_secretbox_NONCEBYTES,
                 user_val.mv_data, key),
             "failed to decrypt");
      printf("%.*s\n", (int)decrypted_len, decrypted);
      free(decrypted);
    }
  } else if (cmd == KvPut) {
    u64 encrypted_len = user_val.mv_size + crypto_secretbox_NONCEBYTES +
                        crypto_secretbox_MACBYTES;
    u8 *encrypted = malloc(encrypted_len);
    randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
    CHECK0(crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES,
                                 user_val.mv_data, user_val.mv_size, encrypted,
                                 key));
    user_val.mv_data = encrypted;
    user_val.mv_size = encrypted_len;

    CHECK0(mdb_txn_begin(kv, 0, 0, &txn));
    CHECK0(mdb_put(txn, db, &user_key, &user_val, 0));
    CHECK0(mdb_txn_commit(txn));

    free(encrypted);
  } else
    CHECK(false);

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

int demo_getkey(Str seed_str, CryptoSignPK *pk, CryptoSignSK *sk) {
  CryptoSeed seed;
  sodium_hex2bin((u8 *)&seed, sizeof(seed), (char *)seed_str.buf, seed_str.len,
                 0, 0, 0);
  if (crypto_sign_seed_keypair((u8 *)pk, (u8 *)sk, (u8 *)&seed))
    return 1;
  return 0;
}

bool libb58_sha256_impl(void *out, const void *msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}

int demo_b58(int argc, const char **argv) {
  b58_sha256_impl = libb58_sha256_impl;

  // Hex string encodes 1-byte version + payload
  Str hex = str_from_c("165a1fc5dd9e6f03819fca94a2d89669469667f9a0");
  u8 bin[21];
  CHECK(sizeof(bin) * 2 == hex.len);
  bytes_from_hex(hex, bin, sizeof(bin));
  phex("orig", bin, sizeof(bin));

  // encode
  char b58[sizeof(bin) * 2];
  size_t b58_len = sizeof(b58);
  CHECK(b58check_enc(b58, &b58_len, bin[0], &bin[1], sizeof(bin) - 1));
  printf("b58c(%zu)=%s\n", b58_len - 1, b58);

  // decode
  u8 bin2[sizeof(bin) + 4];
  size_t bin2_len = sizeof(bin2);
  CHECK(b58tobin(bin2, &bin2_len, b58, b58_len - 1));

  // Last 4 bytes are the checksum
  phex("deco", bin2, bin2_len - 4);
  CHECK0(memcmp(bin2, bin, bin2_len - 4));

  // b58check returns the version byte
  CHECK(b58check(bin2, bin2_len, b58, b58_len) == 0x16);

  return 0;
}

static const char *const usages[] = {
    "pk [options] [cmd] [args]\n\n    Commands:"
    "\n      - demo-x3dh"
    "\n      - demo-kv"
    "\n      - demo-nik"
    "\n      - demo-b58",
    NULL,
};

struct cmd_struct {
  const char *cmd;
  int (*fn)(int, const char **);
};

static struct cmd_struct commands[] = {
    {"demo-x3dh", demo_x3dh},
    {"demo-kv", demo_kv},
    {"demo-nik", demo_nik},
    {"demo-b58", demo_b58},
};

typedef struct {
  int argc;
  const char **argv;
} MainCoroCtx;

void coro_exit(u8 code) { mco_push(mco_running(), &code, 1); }

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

void *mco_alloc(size_t size, void *udata) {
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
  if (mco_get_storage_size(co) > 0)
    mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  uv_loop_close(loop);
  free(loop);

  LOG("goodbye (code=%d)", rc);
  return rc;
}
