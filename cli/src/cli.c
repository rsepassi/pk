#define _POSIX_C_SOURCE 199309L  // for CLOCK_MONOTONIC in time.h
#include <time.h>
#undef _POSIX_C_SOURCE

#include <arpa/inet.h>

// vendor deps
#include "argparse.h"
#include "libbase58.h"
#include "lmdb.h"
#include "mimalloc.h"
#include "minicoro.h"
#include "ngtcp2/ngtcp2.h"
#include "plum/plum.h"
#include "uv.h"
#include "vterm.h"

// lib
#include "allocatormi.h"
#include "base64.h"
#include "bip39.h"
#include "crypto.h"
#include "getpass.h"
#include "hashmap.h"
#include "keyio.h"
#include "list.h"
#include "log.h"
#include "nik.h"
#include "nik_cxn.h"
#include "queue.h"
#include "signal.h"
#include "stdmacros.h"
#include "stdtypes.h"
#include "taia.h"
#include "uvco.h"

#define MAX_PW_LEN 2048

// Global event loop
uv_loop_t* loop;

// Some constant data
char* A_to_B_message = "hello world";
char* A_seed_hex =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char* B_seed_hex =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

static void bytes_from_hex(Str s, u8* out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char*)s.buf, s.len, 0, 0, 0);
}

// Printing
static void phex(char* tag, u8* b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i)
    printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8*)&(k), sizeof(k))

static int nik_keys_kx_from_seed(const CryptoSeed* seed, CryptoKxKeypair* out) {
  CryptoSignPK pk;
  CryptoSignSK sk;
  if (crypto_sign_seed_keypair((u8*)&pk, (u8*)&sk, (u8*)seed))
    return 1;

  if (crypto_sign_ed25519_pk_to_curve25519((u8*)&out->pk, (u8*)&pk))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8*)&out->sk, (u8*)&sk))
    return 1;
  return 0;
}

static void CxnCb(NIK_Cxn* cxn, void* userdata, NIK_Cxn_Event e, Bytes data,
                  u64 now) {
  LOGS(data);
}

static int demo_nikcxn(int argc, const char** argv) {
  CryptoKxKeypair kx_keys_i;
  {
    Str A_seed_str = str_from_c(A_seed_hex);
    CryptoSeed A_seed;
    sodium_hex2bin((u8*)&A_seed, sizeof(A_seed), (char*)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &kx_keys_i));
  }

  CryptoKxKeypair kx_keys_r;
  {
    Str B_seed_str = str_from_c(B_seed_hex);
    CryptoSeed B_seed;
    sodium_hex2bin((u8*)&B_seed, sizeof(B_seed), (char*)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &kx_keys_r));
  }

  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk, 0};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk, 0};

  NIK_Cxn cxn_A;
  u64 ctx_A;
  NIK_Cxn cxn_B;
  u64 ctx_B;
  LOG("cxn_A=%p", &cxn_A);
  LOG("cxn_B=%p", &cxn_B);

  Bytes zero = BytesZero;
  u64 maxdelay = UINT64_MAX;
  u64 now = 1;

  // Initialize A as initiator
  nik_cxn_init(&cxn_A, hkeys_A, CxnCb, &ctx_A);

  // I2R
  Bytes hs1;
  {
    // A enqueues message
    Bytes msg1 = Str("hi from A");
    nik_cxn_enqueue(&cxn_A, msg1);
    LOG("A initiates handshake");
    ++now;
    u64 delay_A = nik_cxn_get_next_wait_delay(&cxn_A, now, maxdelay);
    CHECK(delay_A == 0);
    CHECK(nik_cxn_outgoing(&cxn_A, &hs1, now) == NIK_Cxn_Status_MsgReady);
    CHECK0(nik_cxn_outgoing(&cxn_A, &zero, now));
  }

  // R2I
  Bytes hs2;
  {
    LOG("B responds to handshake");
    CHECK(hs1.len == sizeof(NIK_HandshakeMsg1));
    NIK_HandshakeMsg1* msg1 = (NIK_HandshakeMsg1*)hs1.buf;
    NIK_Handshake hs;
    CHECK0(nik_handshake_init_check(&hs, hkeys_B, msg1));
    nik_cxn_init_responder(&cxn_B, hkeys_B, &hs, msg1, CxnCb, &ctx_B, now);
    LOGB(CryptoBytes(cxn_B.next.send));
    LOGB(CryptoBytes(cxn_B.next.recv));
    CHECK0(cxn_B.current_start_time);
    CHECK0(nik_cxn_get_next_wait_delay(&cxn_B, now, maxdelay));
    CHECK(nik_cxn_outgoing(&cxn_B, &hs2, now) == NIK_Cxn_Status_MsgReady);
    CHECK0(nik_cxn_outgoing(&cxn_B, &zero, now));
    CHECK(cxn_B.handshake_state == NIK_CxnHState_R_DataWait);
  }
  free(hs1.buf);

  // Data msg
  Bytes data;
  {
    // Delivering the handshake response finalizes the handshake and triggers
    // the message to be delivered.
    LOG("A finalizes handshake");
    ++now;
    nik_cxn_incoming(&cxn_A, hs2, now);

    LOGB(CryptoBytes(cxn_A.current.send));
    LOGB(CryptoBytes(cxn_A.current.recv));
    CHECK0(sodium_memcmp(&cxn_A.current.send, &cxn_B.next.recv,
                         sizeof(cxn_A.current.send)));
    CHECK0(sodium_memcmp(&cxn_A.current.recv, &cxn_B.next.send,
                         sizeof(cxn_A.current.send)));
    CHECK(cxn_A.handshake_state == NIK_CxnHState_Null);
    CHECK0(nik_cxn_get_next_wait_delay(&cxn_A, now, maxdelay));

    LOG("A sends message");
    CHECK(nik_cxn_outgoing(&cxn_A, &data, now) == NIK_Cxn_Status_MsgReady);
    CHECK0(nik_cxn_outgoing(&cxn_A, &zero, now));
  }
  free(hs2.buf);

  // Data msg incoming
  {
    // The delivery of the first data message finalizes B's handshake
    LOG("B receives message");
    ++now;
    CHECK(cxn_B.handshake_state == NIK_CxnHState_R_DataWait);
    nik_cxn_incoming(&cxn_B, data, now);
    CHECK(cxn_B.handshake_state == NIK_CxnHState_Null);
    CHECK0(sodium_memcmp(&cxn_A.current.send, &cxn_B.current.recv,
                         sizeof(cxn_A.current.send)));
    CHECK0(sodium_memcmp(&cxn_A.current.recv, &cxn_B.current.send,
                         sizeof(cxn_A.current.send)));
  }
  free(data.buf);

  // Keepalive
  Bytes keepalive;
  {
    u64 delay = nik_cxn_get_next_wait_delay(&cxn_B, now, maxdelay);
    now += delay;
    LOG("B sends keepalive after %dms", (int)delay);
    CHECK0(nik_cxn_get_next_wait_delay(&cxn_B, now, maxdelay));
    CHECK(nik_cxn_outgoing(&cxn_B, &keepalive, now) == NIK_Cxn_Status_MsgReady);
    CHECK0(nik_cxn_outgoing(&cxn_B, &zero, now));
    CHECK(keepalive.buf[0] == NIK_Msg_Keepalive);
  }

  u64 rekey_delay =
      (NIK_LIMIT_REKEY_TIMEOUT_SECS + NIK_LIMIT_KEEPALIVE_TIMEOUT_SECS) * 1000;
  {
    nik_cxn_incoming(&cxn_A, keepalive, now);
    CHECK0(nik_cxn_outgoing(&cxn_A, &zero, now));
    // Next delay is for rekey
    CHECK(nik_cxn_get_next_wait_delay(&cxn_A, now, UINT64_MAX) == rekey_delay);
  }
  free(keepalive.buf);

  // Trigger a key rotation
  {
    LOG("Trigger key rotation");
    // Both are put into StartWait
    now += rekey_delay;
    CHECK0(nik_cxn_get_next_wait_delay(&cxn_A, now, UINT64_MAX));
    CHECK0(nik_cxn_get_next_wait_delay(&cxn_B, now, UINT64_MAX));
    CHECK(cxn_A.handshake_state == NIK_CxnHState_I_StartWait);
    CHECK(cxn_B.handshake_state == NIK_CxnHState_I_StartWait);

    // Determine which one has the shorter jitter timeout
    u64 delay_A = cxn_A.handshake.initiator.handshake_start_time;
    u64 delay_B = cxn_B.handshake.initiator.handshake_start_time;
    u64 delay = MIN(delay_A, delay_B);
    NIK_Cxn* initiator = delay == delay_A ? &cxn_A : &cxn_B;
    NIK_Cxn* responder = delay == delay_A ? &cxn_B : &cxn_A;
    now += delay;

    LOG("Initiator sends handshake");
    CHECK(nik_cxn_outgoing(initiator, &hs1, now) == NIK_Cxn_Status_MsgReady);
    CHECK(initiator->handshake_state == NIK_CxnHState_I_R2IWait);
    LOG("Responder receives handshake");
    nik_cxn_incoming(responder, hs1, now);
    CHECK(responder->handshake_state == NIK_CxnHState_R_R2IReady);
    LOG("Responder responds");
    CHECK(nik_cxn_outgoing(responder, &hs2, now) == NIK_Cxn_Status_MsgReady);
    LOG("Initiator finalizes");
    nik_cxn_incoming(initiator, hs2, now);
    CHECK(responder->handshake_state == NIK_CxnHState_R_DataWait);
    CHECK(initiator->handshake_state == NIK_CxnHState_Null);

    LOG("Initiator sends data");
    nik_cxn_enqueue(initiator, Str("complete"));
    CHECK(nik_cxn_outgoing(initiator, &data, now) == NIK_Cxn_Status_MsgReady);
    LOG("Responder finalizes");
    nik_cxn_incoming(responder, data, now);
    CHECK(responder->handshake_state == NIK_CxnHState_Null);

    free(hs1.buf);
    free(hs2.buf);
    free(data.buf);
  }

  nik_cxn_deinit(&cxn_A);
  nik_cxn_deinit(&cxn_B);

  return 0;
}

static int demo_nik(int argc, const char** argv) {
  CryptoKxKeypair kx_keys_i;
  {
    Str A_seed_str = str_from_c(A_seed_hex);
    CryptoSeed A_seed;
    sodium_hex2bin((u8*)&A_seed, sizeof(A_seed), (char*)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &kx_keys_i));
  }

  CryptoKxKeypair kx_keys_r;
  {
    Str B_seed_str = str_from_c(B_seed_hex);
    CryptoSeed B_seed;
    sodium_hex2bin((u8*)&B_seed, sizeof(B_seed), (char*)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &kx_keys_r));
  }

  u32 id_i = 1;
  u32 id_r = 2;
  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk, 0};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk, 0};

  // I
  LOG("i2r");
  NIK_Handshake state_i;
  NIK_HandshakeMsg1 msg1;
  CHECK0(nik_handshake_init(&state_i, hkeys_A, id_i, &msg1));
  phex("IC", state_i.chaining_key, NIK_CHAIN_SZ);

  // R
  LOG("i2r check");
  NIK_Handshake state_r;
  CHECK0(nik_handshake_init_check(&state_r, hkeys_B, &msg1));
  phex("RC", state_r.chaining_key, NIK_CHAIN_SZ);

  // R
  LOG("r2i");
  NIK_HandshakeMsg2 msg2;
  CHECK0(nik_handshake_respond(&state_r, id_r, &msg1, &msg2));
  phex("RC", state_r.chaining_key, NIK_CHAIN_SZ);

  // I
  LOG("r2i check");
  CHECK0(nik_handshake_respond_check(&state_i, &msg2));
  phex("IC", state_i.chaining_key, NIK_CHAIN_SZ);

  // I
  LOG("i derive");
  NIK_Session tx_i;
  CHECK0(nik_handshake_final(&state_i, &tx_i));

  // R
  LOG("r derive");
  NIK_Session tx_r;
  CHECK0(nik_handshake_final(&state_r, &tx_r));

  // Check that I and R have the same transfer keys
  phex("tx.send", (u8*)&tx_i.send, sizeof(tx_i.send));
  phex("tx.recv", (u8*)&tx_i.recv, sizeof(tx_i.recv));
  CHECK0(sodium_memcmp(&tx_i.send, &tx_r.recv, sizeof(tx_i.send)));
  CHECK0(sodium_memcmp(&tx_i.recv, &tx_r.send, sizeof(tx_i.send)));
  CHECK(tx_i.send_n == 0);
  CHECK(tx_i.recv_n == 0);
  CHECK(tx_r.send_n == 0);
  CHECK(tx_r.recv_n == 0);
  CHECK(tx_r.counter_max == 0);
  CHECK(tx_i.local_idx == tx_r.remote_idx);
  CHECK(tx_i.remote_idx == tx_r.local_idx);

  // I: Send a message
  Str payload = Str("hello!");
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
  payload = Str("ahoy!");
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
  CHECK(tx_r.counter_max == 2);

  return 0;
}

typedef struct {
  MDB_env* kv;
  MDB_dbi db;
  CryptoBoxKey key;
  Allocator allocator;
} CryptKv;

static int cryptkv_keycrypt(CryptKv* kv, Bytes key, Bytes* out) {
  // Encrypt the key with a nonce derived from the key
  int rc = 1;
  u64 ekey_len = key.len + crypto_secretbox_MACBYTES;
  if (Alloc_alloc(kv->allocator, out, u8, ekey_len))
    goto end;
  u8 nonce[crypto_secretbox_NONCEBYTES];
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(kv->key));
  if (crypto_kdf_hkdf_sha256_expand(nonce, sizeof(nonce), (const char*)key.buf,
                                    key.len, (u8*)&kv->key))
    goto err;
  STATIC_CHECK(crypto_secretbox_KEYBYTES == sizeof(kv->key));
  if (crypto_secretbox_easy(out->buf, key.buf, key.len, nonce, (u8*)&kv->key))
    goto err;

  rc = 0;
  goto end;

err:
  allocator_free(kv->allocator, *out);
end:
  return rc;
}

static int cryptkv_put(CryptKv* kv, Bytes key, Bytes val) {
  int rc = 1;

  Bytes ekey = {0};
  if (cryptkv_keycrypt(kv, key, &ekey))
    goto end;

  MDB_txn* txn;
  if (mdb_txn_begin(kv->kv, 0, 0, &txn))
    goto end;

  u64 elen = val.len + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
  Bytes eval = {0};
  if (Alloc_alloc(kv->allocator, &eval, u8, elen))
    goto end;
  randombytes_buf(eval.buf, crypto_secretbox_NONCEBYTES);

  if (crypto_secretbox_easy(eval.buf + crypto_secretbox_NONCEBYTES, val.buf,
                            val.len, eval.buf, (u8*)&kv->key))
    goto end2;

  MDB_val mk = {ekey.len, ekey.buf};
  MDB_val mv = {eval.len, eval.buf};

  if (mdb_txn_begin(kv->kv, 0, 0, &txn))
    goto end2;
  if (mdb_put(txn, kv->db, &mk, &mv, 0))
    goto end2;
  if (mdb_txn_commit(txn))
    goto end2;

  rc = 0;

end2:
  allocator_free(kv->allocator, eval);
end:
  allocator_free(kv->allocator, ekey);
  return rc;
}

static int cryptkv_get(CryptKv* kv, Bytes key, Bytes* val) {
  STATIC_CHECK(MDB_NOTFOUND < 0);

  int rc = 1;

  Bytes ekey = {0};
  if (cryptkv_keycrypt(kv, key, &ekey))
    goto end;

  MDB_txn* txn;
  if (mdb_txn_begin(kv->kv, 0, MDB_RDONLY, &txn))
    goto end;

  MDB_val mk = {ekey.len, ekey.buf};
  MDB_val mv;
  rc = mdb_get(txn, kv->db, &mk, &mv);
  mdb_txn_commit(txn);
  if (rc)
    goto end;
  rc = 1;

  u64 decrypted_len =
      mv.mv_size - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  Alloc_alloc(kv->allocator, val, u8, decrypted_len);

  if (crypto_secretbox_open_easy(
          val->buf, mv.mv_data + crypto_secretbox_NONCEBYTES,
          mv.mv_size - crypto_secretbox_NONCEBYTES, mv.mv_data, (u8*)&kv->key))
    goto end;

  rc = 0;

end:
  allocator_free(kv->allocator, ekey);
  return rc;
}

static int cryptkv_open(CryptKv** kv_ptr, const char* kv_path,
                        CryptoBoxKey* key, Allocator allocator) {
  *kv_ptr = sodium_malloc(sizeof(CryptKv));
  CryptKv* kv = *kv_ptr;
  *kv = (CryptKv){0};

  kv->key = *key;
  kv->allocator = allocator;
  sodium_memzero(key, sizeof(CryptoBoxKey));

  uv_fs_t req;
  if (uvco_fs_stat(loop, &req, kv_path)) {
    fprintf(stderr,
            "error: kv path does not exist. Specify a path or pass --create. "
            "path=%s\n",
            kv_path);
    goto err;
  }

  if (!S_ISDIR(req.statbuf.st_mode)) {
    fprintf(stderr, "kv path must be a directory: %s", kv_path);
    goto err;
  }
  uv_fs_req_cleanup(&req);

  mode_t kv_mode = S_IRUSR | S_IWUSR | S_IRGRP;  // rw-r-----
  if (mdb_env_create(&kv->kv))
    goto err;
  if (mdb_env_open(kv->kv, kv_path, MDB_NOLOCK, kv_mode))
    goto err;

  MDB_txn* txn;
  if (mdb_txn_begin(kv->kv, 0, 0, &txn))
    goto err;
  if (mdb_dbi_open(txn, 0, 0, &kv->db))
    goto err;
  if (mdb_txn_commit(txn))
    goto err;

  return 0;

err:
  sodium_free(*kv_ptr);
  return 1;
}

static void cryptkv_close(CryptKv* kv) {
  mdb_env_close(kv->kv);
  sodium_memzero(kv, sizeof(CryptKv));
  sodium_free(kv);
}

static int demo_kv(int argc, const char** argv) {
  struct argparse argparse;
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_END(),
  };
  const char* const usages[] = {"kv [options] get <db> <key>",
                                "kv [options] put <db> <key> <value>", NULL};
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  if (argc < 3) {
    argparse_usage(&argparse);
    return 1;
  }

  // get or put
  enum {
    KvNone,
    KvGet,
    KvPut
  } cmd = strcmp(argv[1], "get") == 0   ? KvGet
          : strcmp(argv[1], "put") == 0 ? KvPut
                                        : KvNone;
  if (cmd == KvNone) {
    fprintf(stderr, "error: must specify get or put\n");
    return 1;
  } else if (cmd == KvPut) {
    if (argc != 4) {
      fprintf(stderr, "error: put expects a key and a value");
      return 1;
    }
  }

  Bytes key = str_from_c(argv[2]);
  Bytes val = cmd == KvPut ? str_from_c(argv[3]) : BytesZero;

  Allocator allocator = allocator_libc();
  CryptoBoxKey kvkey = {{1, 2, 3, 4}};

  CryptKv* kv;
  CHECK0(cryptkv_open(&kv, "/tmp/crypt", &kvkey, allocator));
  if (cmd == KvGet) {
    int rc = cryptkv_get(kv, key, &val);
    if (rc == MDB_NOTFOUND) {
      fprintf(stderr, "key not found\n");
      return 1;
    }
    CHECK0(rc);
    printf("%.*s\n", (int)val.len, val.buf);
  } else {
    CHECK(cmd == KvPut);
    CHECK0(cryptkv_put(kv, key, val));
  }
  cryptkv_close(kv);
  return 0;
}

static int demosshkeyread(int argc, const char** argv) {
  CHECK(argc == 2, "must provide a key path");
  const char* path = argv[1];

  Allocator al = allocatormi_heap();
  CryptoAllocator cryptal = {al};
  Allocator sal = allocator_crypto(&cryptal);

  usize sz = 1024;
  Bytes str;  // SECRET
  CHECK0(allocator_u8(sal, &str, sz));

  uv_file fd;
  CHECK0(uvco_fs_open(loop, path, UV_FS_O_RDONLY, 0, &fd));
  CHECK0(uvco_fs_read(loop, fd, &str, 0));
  uvco_fs_close(loop, fd);
  LOG("read %d", (int)str.len);
  CHECK(str.len < sz);

  CryptoSignSK sk;
  CHECK0(keyio_keydecode_openssh(str, sal, &sk));
  LOGB(CryptoBytes(sk));

  // Free
  allocator_free(sal, str);
  allocator_deinit(al);

  return 0;
}

static int demo_bip39(int argc, const char** argv) {
  // Generate 32 bytes of entropy
  u8 key_buf[32];
  randombytes_buf(key_buf, sizeof(key_buf));
  Bytes key = {sizeof(key_buf), key_buf};
  LOGB(key);

  // Convert it to a word list
  u16 word_idxs[bip39_MNEMONIC_LEN(sizeof(key_buf))];
  CHECK0(bip39_mnemonic_idxs(key, word_idxs));
  for (usize i = 0; i < ARRAY_LEN(word_idxs); ++i) {
    LOG("%02d. %04d %s", (int)(i + 1), word_idxs[i], bip39_words[word_idxs[i]]);
  }

  // Verify that it decodes properly
  u8 dec_buf[sizeof(key_buf)];
  Bytes dec = {sizeof(key_buf), dec_buf};
  CHECK0(bip39_mnemonic_bytes(word_idxs, ARRAY_LEN(word_idxs), &dec));
  CHECK0(memcmp(key_buf, dec_buf, sizeof(key_buf)));

  // From mnemonic to seed:
  // Password Hash: Argon2id (Bitcoin uses PBKDF2)
  // Password = joined mnemonic words
  // Salt = "mnemonic" + passphrase

  return 0;
}

static int demo_base64(int argc, const char** argv) {
  Str a = Str("hello world!");

  Str enc;
  {
    usize sz = base64_encoded_maxlen(a.len);
    enc = (Str){sz, malloc(sz)};
  }

  CHECK0(base64_encode(a, &enc));
  LOGS(enc);

  Str dec;
  {
    usize sz = base64_decoded_maxlen(enc.len);
    dec = (Str){sz, malloc(sz)};
  }

  CHECK0(base64_decode(enc, &dec));
  LOGS(dec);

  CHECK(a.len == dec.len);
  CHECK(memcmp(a.buf, dec.buf, a.len) == 0);

  free(enc.buf);
  free(dec.buf);
  return 0;
}

static void vt_cb(const char* s, size_t len, void* user) {
  LOG("vt(%d)=%.*s", (int)len, (int)len, s);
}

static int demo_vterm(int argc, const char** argv) {
  int rows = 100;
  int cols = 80;
  VTerm* vt = vterm_new(rows, cols);
  vterm_set_utf8(vt, true);

  VTermScreen* vt_screen = vterm_obtain_screen(vt);
  vterm_screen_reset(vt_screen, true);

  // VTermState *vt_state = vterm_obtain_state(vt);
  // vterm_state_reset(vt_state, 1);

  Str txt = Str("hi!");
  vterm_input_write(vt, (char*)txt.buf, txt.len);

  vterm_output_set_callback(vt, vt_cb, NULL);
  vterm_keyboard_unichar(vt, 65, 0);
  vterm_keyboard_key(vt, VTERM_KEY_ENTER, 0);

  vterm_free(vt);
  return 0;
}

static void get_identity_key(Str hex, CryptoSignSK* out) {
  CHECK(hex.len == 64, "got length %d", (int)hex.len);
  CryptoSeed seed;
  sodium_hex2bin((u8*)&seed, sizeof(CryptoSeed), (char*)hex.buf, hex.len, 0, 0,
                 0);

  CryptoSignPK pk;
  CHECK0(crypto_sign_seed_keypair((u8*)&pk, (u8*)out, (u8*)&seed));
}

static int drat_a_to_b(DratState* A_state, X3DH* A_x, DratState* B_state,
                       X3DH* B_x, Str msg) {
  LOGS(msg);

  // A sends
  Bytes A_ad = {sizeof(A_x->ad), A_x->ad};
  DratHeader header;
  usize cipher_sz = drat_encrypt_len(msg.len);
  Bytes cipher = {cipher_sz, malloc(cipher_sz)};
  if (drat_encrypt(A_state, msg, A_ad, &header, &cipher))
    return 1;

  // B receives
  Bytes B_ad = {sizeof(B_x->ad), B_x->ad};
  if (drat_decrypt(B_state, &header, cipher, B_ad))
    return 1;

  // decrypt(encrypt(msg)) == msg
  CHECK(msg.len == cipher.len);
  if (memcmp(cipher.buf, msg.buf, msg.len))
    return 1;
  LOGS(cipher);
  free(cipher.buf);
  return 0;
}

static int demo_drat(int argc, const char** argv) {
  // Alice and Bob identity keys
  CryptoSignSK A_key;
  get_identity_key(str_from_c(A_seed_hex), &A_key);
  CryptoSignSK B_key;
  get_identity_key(str_from_c(B_seed_hex), &B_key);

  // X3DH
  X3DHKeys A_sec;
  X3DHKeys B_sec;
  X3DH A_x;
  X3DH B_x;
  {
    CHECK0(x3dh_keys_init(&A_key, &A_sec));
    CHECK0(x3dh_keys_init(&B_key, &B_sec));
    X3DHHeader A_header;
    CHECK0(x3dh_init(&A_sec, &B_sec.pub, &A_header, &A_x));
    CHECK0(x3dh_init_recv(&B_sec, &A_header, &B_x));
    CHECK0(memcmp((u8*)&A_x, (u8*)&B_x, sizeof(X3DH)));
  }

  // Initialize double ratchet
  DratState B_state;
  DratInit B_init = {
      .session_key = &B_x.key,
      .pk = &B_sec.pub.kx_prekey,
      .sk = &B_sec.sec.kx_prekey,
  };
  CHECK0(drat_init(&B_state, &B_init));

  DratState A_state;
  DratInitRecv A_init = {
      .session_key = &A_x.key,
      .bob = &B_sec.pub.kx_prekey,
  };
  CHECK0(drat_init_recv(&A_state, &A_init));

  // Send some messages back and forth
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state,
                     &A_x,  //
                     Str("hello from Bob! secret number is 77")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state,
                     &A_x,  //
                     Str("hello from Bob! secret number is 79")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state,
                     &B_x,  //
                     Str("hello from Alice!")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state,
                     &A_x,  //
                     Str("roger roger")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state,
                     &A_x,  //
                     Str("roger roger 2")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state,
                     &B_x,  //
                     Str("1")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state,
                     &B_x,  //
                     Str("2")));

  return 0;
}

static int demo_x3dh(int argc, const char** argv) {
  CryptoSignSK A_key;
  get_identity_key(str_from_c(A_seed_hex), &A_key);
  CryptoSignSK B_key;
  get_identity_key(str_from_c(B_seed_hex), &B_key);

  // Alice init
  X3DHKeys A_sec;
  CHECK0(x3dh_keys_init(&A_key, &A_sec));

  // Bob init
  X3DHKeys B_sec;
  CHECK0(x3dh_keys_init(&B_key, &B_sec));

  // Alice sends X3DHHeader and derives key
  X3DH A_x;
  X3DHHeader A_header;
  CHECK0(x3dh_init(&A_sec, &B_sec.pub, &A_header, &A_x));

  // Bob receives X3DHHeader and derives key
  X3DH B_x;
  CHECK0(x3dh_init_recv(&B_sec, &A_header, &B_x));

  // Keys + AD are equal
  CHECK0(memcmp((u8*)&A_x, (u8*)&B_x, sizeof(X3DH)));
  LOG("keys match!");

  return 0;
}

static bool libb58_sha256_impl(void* out, const void* msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}

static int demo_b58(int argc, const char** argv) {
  b58_sha256_impl = libb58_sha256_impl;

  // Hex string encodes 1-byte version + payload
  Str hex = Str("165a1fc5dd9e6f03819fca94a2d89669469667f9a0");
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

static void alloc_cb(uv_handle_t* handle, size_t suggested_size,
                     uv_buf_t* buf) {
  *buf = uv_buf_init(malloc(suggested_size), (int)suggested_size);
}

static void recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                    const struct sockaddr* addr, unsigned flags) {
  if (nread == 0 && addr == NULL) {
    LOG("<EOS>");
    return;
  }
  if (nread < 0) {
    LOG("error!");
    free(buf->base);
    return;
  }
  LOG("msg len=%d", (int)nread);
  LOG("msg %.*s", (int)nread, buf->base);
  free(buf->base);
}

static void mapping_callback(int id, plum_state_t state,
                             const plum_mapping_t* mapping) {
  LOG("map!");
  CHECK(state == PLUM_STATE_SUCCESS);
  LOG("External address: %s:%hu\n", mapping->external_host,
      mapping->external_port);
}

static int demo_multicast(int argc, const char** argv) {
  bool send = argc > 1 && memcmp(argv[1], "send", 4) == 0;

  LOG("udp init");
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  char* multicast_group = "239.0.0.22";
  int port = 20000;

  if (send) {
    struct sockaddr_in myaddr;
    CHECK0(uv_ip4_addr("0.0.0.0", 0, &myaddr));
    CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));

    struct sockaddr_storage localbind;
    int len;
    CHECK0(uv_udp_getsockname(&udp, (struct sockaddr*)&localbind, &len));
    LOG("addrlen=%d", len);
    // LOG("addr=%u", ((struct sockaddr_in*)&localbind)->sin_addr.s_addr);

    LOG("udp send");
    struct sockaddr_in multi_addr;
    CHECK0(uv_ip4_addr(multicast_group, port, &multi_addr));
    Str peer_id = Str("mike multicast");
    uv_buf_t buf = uv_buf_init((char*)peer_id.buf, (int)peer_id.len);
    CHECK0(uvco_udp_send(&udp, &buf, 1, (struct sockaddr*)&multi_addr));
    LOG("sent!");
    uvco_sleep(loop, 1000);
  } else {
    struct sockaddr_in myaddr;
    CHECK0(uv_ip4_addr("0.0.0.0", port, &myaddr));

    CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));
    CHECK0(uv_udp_set_membership(&udp, multicast_group, NULL, UV_JOIN_GROUP));

    LOG("udp recv multicast on %s %d", multicast_group, port);
    CHECK0(uv_udp_recv_start(&udp, alloc_cb, recv_cb));

    uvco_sleep(loop, 60000);
    uv_udp_recv_stop(&udp);
  }
  return 0;
}

static int demo_holepunch(int argc, const char** argv) {
  // TODO:
  // Hit discovery server to get peer_addr

  // Hard-coding for now
  struct sockaddr_in peer_addr;
  CHECK0(uv_ip4_addr("75.164.165.93", 8087, &peer_addr));

  // Plum
  plum_config_t config = {0};
  config.log_level = PLUM_LOG_LEVEL_WARN;
  plum_init(&config);
  plum_mapping_t mapping = {0};
  mapping.protocol = PLUM_IP_PROTOCOL_UDP;
  mapping.internal_port = 20000;
  int mapping_id = plum_create_mapping(&mapping, mapping_callback);
  struct sockaddr_in myaddr;
  CHECK0(uv_ip4_addr("0.0.0.0", 20000, &myaddr));

  LOG("udp init");
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  LOG("udp send");
  Str peer_id = Str("mike multicast");
  uv_buf_t buf = uv_buf_init((char*)peer_id.buf, (int)peer_id.len);
  CHECK0(uvco_udp_send(&udp, &buf, 1, (struct sockaddr*)&peer_addr));
  LOG("sent!");

  LOG("udp recv");
  CHECK0(uv_udp_recv_start(&udp, alloc_cb, recv_cb));
  uvco_sleep(loop, 60000);
  uv_udp_recv_stop(&udp);

  plum_destroy_mapping(mapping_id);

  // TODO: Start sending messages to peer address

  return 0;
}

static void do_some_allocs(Allocator a) {
  Bytes b1 = {0};
  Alloc_alloc(a, &b1, u8, 16);
  CHECK(b1.len == 16);

  Bytes b2 = {0};
  Alloc_alloc(a, &b2, usize, 16);
  CHECK(b2.len == (sizeof(usize) * 16));

  allocator_free(a, b1);
  allocator_free(a, b2);

  allocator_deinit(a);
}

static int demo_mimalloc(int argc, const char** argv) {
  // MIMALLOC_SHOW_STATS=1
  mi_option_enable(mi_option_show_stats);

  Allocator a1 = allocatormi_allocator();
  do_some_allocs(a1);

  Allocator a2 = allocatormi_heap();
  do_some_allocs(a2);

  {
    Bytes x = allocatormi_block_alloc(1);
    Allocator a3 = allocatormi_arena(x, true);
    do_some_allocs(a3);
    allocatormi_block_free(x);
  }

  {
    Bytes x = {1024, malloc(1024)};
    BumpAllocator b;
    Allocator a4 = allocator_bump(&b, x);
    do_some_allocs(a4);
    LOG("i=%d", (int)b.i);
    free(x.buf);
  }

  return 0;
}

static int pw_prompt(Bytes* b) {
  char* pw = sodium_malloc(MAX_PW_LEN);
  b->buf = (u8*)pw;
  fprintf(stderr, "pw > ");
  ssize_t pw_len = getpass(pw, MAX_PW_LEN);
  if (pw_len > 0)
    b->len = pw_len;
  if (pw_len < 0)
    return 1;
  return 0;
}

static int demo_keyread(int argc, const char** argv) {
  CHECK(argc == 2, "must pass a path");
  const char* path = argv[1];

  // al is our general-purpose allocator
  Allocator al = allocatormi_allocator();
  CryptoAllocator cryptal_base = {al};
  // sal is our secrets allocator
  Allocator sal = allocator_crypto(&cryptal_base);

  u8 contents_buf[256];
  Bytes contents = bytes_from_arr(contents_buf);

  uv_file fd;
  CHECK0(uvco_fs_open(loop, path, UV_FS_O_RDONLY, 0, &fd));
  CHECK0(uvco_fs_read(loop, fd, &contents, 0));
  uvco_fs_close(loop, fd);
  LOG("read %d", (int)contents.len);
  CHECK(contents.len < 256);

  CryptoSignSK sk;
  Bytes pw = {0};
  CHECK0(keyio_keydecode(contents, pw, &sk));
  LOGB(CryptoBytes(sk));

  allocator_deinit(sal);
  allocator_deinit(al);
  return 0;
}

static int demo_keygen(int argc, const char** argv) {
  // al is our general-purpose allocator
  Allocator al = allocatormi_allocator();
  CryptoAllocator cryptal_base = {al};
  // sal is our secrets allocator
  Allocator sal = allocator_crypto(&cryptal_base);

  // Generate a key
  CryptoSignKeypair* keys;
  CHECK0(Alloc_create(sal, &keys));
  CHECK0(crypto_sign_ed25519_keypair((u8*)&keys->pk, (u8*)&keys->sk));
  LOGB(CryptoBytes(keys->sk));

  // Get a passphrase
  u8 pw_buf[2048];
  Bytes pw = bytes_from_arr(pw_buf);
  CHECK0(keyio_getpass(&pw));
  LOGS(pw);

  // Copy it for use in decode (keyencode will zero it out)
  u8 pw_buf2[2048];
  memcpy(pw_buf2, pw_buf, sizeof(pw_buf));
  Bytes pw2 = bytes_from_arr(pw_buf2);
  pw2.len = pw.len;

  // Encode the keys
  Str sk_str;
  Str pk_str;
  CHECK0(keyio_keyencode(keys, pw, sal, &sk_str, &pk_str));
  LOGS(sk_str);
  LOGS(pk_str);

  // Decode the keys
  {
    CryptoSignSK sk;
    if (!keyio_key_is_pwprotected(sk_str))
      pw2 = BytesZero;
    CHECK0(keyio_keydecode(sk_str, pw2, &sk));
    CHECK0(sodium_memcmp((u8*)&sk, (u8*)&keys->sk, sizeof(sk)));
  }

  // Cleanup
  allocator_free(sal, sk_str);
  allocator_free(sal, pk_str);
  Alloc_destroy(sal, keys);

  allocator_deinit(sal);
  allocator_deinit(al);
  return 0;
}

static int demo_pwhash(int argc, const char** argv) {
  Bytes pw;
  CHECK0(pw_prompt(&pw));
  CHECK(pw.len > 0);

  // Hash the password
  u8 pw_hash[crypto_pwhash_STRBYTES];
  u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  CHECK0(crypto_pwhash_str((char*)pw_hash, (char*)pw.buf, pw.len, opslimit,
                           memlimit));
  LOGS(str_from_c((char*)pw_hash));
  CHECK0(crypto_pwhash_str_verify((char*)pw_hash, (char*)pw.buf, pw.len));

  // Derive a key
  u8 salt[crypto_pwhash_SALTBYTES] = {0, 1, 2, 3};
  LOGB(((Bytes){sizeof(salt), salt}));
  u8 key[crypto_secretbox_KEYBYTES];
  {
    u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    CHECK0(crypto_pwhash(key, sizeof(key), (char*)pw.buf, pw.len, salt,
                         opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13));
  }
  return 0;
}

#define TCP2_LOCALHOST "127.0.0.1"
#define TCP2_CIDLEN NGTCP2_MAX_CIDLEN  // 20
#define TCP2_STREAM_DATAGRAM -2
#define CHECK_TCP2(s)                                                          \
  do {                                                                         \
    int __rc = (int)(s);                                                       \
    CHECK(__rc >= 0, "%s: rc=%d %s", #s, __rc, ngtcp2_strerror(__rc));         \
  } while (0)

typedef struct Tcp2Msg {
  Bytes data;
  i64 stream;  // TCP2_STREAM_*, or from ngtcp2_conn_open_{bidi,uni}_stream
  struct Tcp2Msg* _next;
  usize _offset;
} Tcp2Msg;

typedef struct {
  Tcp2Msg* head;
  Tcp2Msg* tail;
} Tcp2MsgQ;

typedef struct {
  Tcp2MsgQ outgoing;
  ngtcp2_conn* conn;
  u8 zerortt_buf[256];
  Bytes zerortt_params;
} Tcp2Ctx;

static void tcp2_outgoing_enqueue(Tcp2Ctx* ctx, Bytes data, i64 stream) {
  Tcp2Msg* node = calloc(1, sizeof(Tcp2Msg));
  node->data = data;
  node->stream = stream;
  if (ctx->outgoing.tail) {
    ctx->outgoing.tail->_next = node;
  } else {
    ctx->outgoing.head = node;
    ctx->outgoing.tail = node;
  }
}

typedef struct {
  u8 secret[1];
  u8 iv[8];
  ngtcp2_crypto_aead_ctx aead;
  ngtcp2_crypto_cipher_ctx cipher;
  ngtcp2_crypto_ctx ctx;
} Tcp2Key;

Tcp2Key* tcp2_key_new() {
  Tcp2Key* k = calloc(1, sizeof(Tcp2Key));
  k->ctx.aead.max_overhead = 0;
  k->ctx.max_encryption = UINT64_MAX;
  k->ctx.max_decryption_failure = 128;
  return k;
}

static int tcp2_crypto_rw(ngtcp2_conn* conn,
                          ngtcp2_encryption_level encryption_level,
                          const uint8_t* data, size_t datalen,
                          void* user_data) {
  // TODO: ngtcp2_conn_set_tls_error on error
  LOG("level=%d", encryption_level);
  Tcp2Ctx* ctx = user_data;
  int rc;

  if (ngtcp2_conn_is_server(conn)) {
    // Server
    switch (encryption_level) {
      case NGTCP2_ENCRYPTION_LEVEL_INITIAL: {
        // Respond to client initial message

        u8 tparams_len = data[0];
        rc = ngtcp2_conn_decode_and_set_remote_transport_params(conn, &data[1],
                                                                tparams_len);
        if (rc != 0)
          return -1;
        CHECK(ngtcp2_conn_get_negotiated_version(conn));

        // Ack the initial message
        {
          Bytes resp;
          resp.len = 8;
          resp.buf = calloc(1, resp.len);
          rc = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, resp.buf, resp.len);
          if (rc != 0)
            return rc;
        }

        // Install 0RTT key
        {
          Tcp2Key* rx = tcp2_key_new();
          ngtcp2_conn_set_0rtt_crypto_ctx(conn, &rx->ctx);
          rc = ngtcp2_conn_install_0rtt_key(conn, &rx->aead, rx->iv,
                                            sizeof(rx->iv), &rx->cipher);
          if (rc != 0)
            return -1;
        }

        // Install the handshake keys
        {
          Tcp2Key* tx = tcp2_key_new();
          rc = ngtcp2_conn_install_tx_handshake_key(
              conn, &tx->aead, tx->iv, sizeof(tx->iv), &tx->cipher);
          if (rc != 0)
            return -1;

          Tcp2Key* rx = tcp2_key_new();
          rc = ngtcp2_conn_install_rx_handshake_key(
              conn, &rx->aead, rx->iv, sizeof(rx->iv), &rx->cipher);
          if (rc != 0)
            return -1;
        }

        // Send the handshake message with transport params + 0rtt params
        {
          Bytes resp;
          resp.len = 512;
          resp.buf = calloc(1, resp.len);

          // Transport params
          {
            ngtcp2_ssize nwrite = ngtcp2_conn_encode_local_transport_params(
                conn, &resp.buf[1], 255);
            if (nwrite < 0)
              return -1;
            resp.buf[0] = (u8)nwrite;
          }

          // 0RTT Transport params
          {
            ngtcp2_ssize nwrite = ngtcp2_conn_encode_0rtt_transport_params(
                conn, &resp.buf[257], 255);
            if (nwrite < 0)
              return -1;
            resp.buf[256] = (u8)nwrite;
          }

          rc = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, resp.buf, resp.len);
          if (rc != 0)
            return rc;
        }

        // Install the txrx keys
        {
          Tcp2Key* tx = tcp2_key_new();
          Tcp2Key* rx = tcp2_key_new();
          rc = ngtcp2_conn_install_tx_key(conn, tx->secret, sizeof(tx->secret),
                                          &tx->aead, tx->iv, sizeof(tx->iv),
                                          &tx->cipher);
          if (rc != 0)
            return -1;
          rc = ngtcp2_conn_install_rx_key(conn, rx->secret, sizeof(rx->secret),
                                          &rx->aead, rx->iv, sizeof(rx->iv),
                                          &rx->cipher);
          if (rc != 0)
            return -1;

          ngtcp2_conn_set_crypto_ctx(conn, &tx->ctx);
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

          Bytes data;
          data.len = 256;
          data.buf = calloc(1, data.len);

          ngtcp2_ssize nwrite = ngtcp2_conn_encode_local_transport_params(
              conn, &data.buf[1], 255);
          if (nwrite < 0)
            return -1;
          data.buf[0] = (u8)nwrite;

          rc = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, data.buf, data.len);
          if (rc != 0)
            return rc;

          // Install 0RTT key
          {
            Tcp2Key* tx = tcp2_key_new();
            ngtcp2_conn_set_0rtt_crypto_ctx(conn, &tx->ctx);
            rc = ngtcp2_conn_install_0rtt_key(conn, &tx->aead, tx->iv,
                                              sizeof(tx->iv), &tx->cipher);
            if (rc != 0)
              return -1;
          }
        } else {
          // Server response
          LOG("server crypto repsonse arrived");

          Tcp2Key* rx = tcp2_key_new();
          rc = ngtcp2_conn_install_rx_handshake_key(
              conn, &rx->aead, rx->iv, sizeof(rx->iv), &rx->cipher);
          if (rc != 0)
            return -1;

          Tcp2Key* tx = tcp2_key_new();
          rc = ngtcp2_conn_install_tx_handshake_key(
              conn, &tx->aead, tx->iv, sizeof(tx->iv), &tx->cipher);
          if (rc != 0)
            return -1;
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
          ctx->zerortt_params.len = data[256];
          ctx->zerortt_params.buf = ctx->zerortt_buf;
          memcpy(ctx->zerortt_params.buf, &data[257], ctx->zerortt_params.len);
        }

        // Ack
        {
          Str data = Str("ok");
          rc = ngtcp2_conn_submit_crypto_data(
              conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, data.buf, data.len);
          if (rc != 0)
            return rc;
        }

        // Mark complete
        {
          Tcp2Key* rx = tcp2_key_new();
          rc = ngtcp2_conn_install_rx_key(conn, rx->secret, sizeof(rx->secret),
                                          &rx->aead, rx->iv, sizeof(rx->iv),
                                          &rx->cipher);
          if (rc != 0)
            return -1;

          Tcp2Key* tx = tcp2_key_new();
          rc = ngtcp2_conn_install_tx_key(conn, tx->secret, sizeof(tx->secret),
                                          &tx->aead, tx->iv, sizeof(tx->iv),
                                          &tx->cipher);
          if (rc != 0)
            return -1;

          ngtcp2_conn_set_crypto_ctx(conn, &tx->ctx);
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
  Tcp2Ctx* ctx = user_data;
  (void)ctx;

  Tcp2Key* rx = tcp2_key_new();
  Tcp2Key* tx = tcp2_key_new();

  int rc = 0;

  ngtcp2_conn_set_initial_crypto_ctx(conn, &tx->ctx);

  rc = ngtcp2_conn_install_initial_key(conn, &rx->aead, rx->iv, &rx->cipher,
                                       &tx->aead, tx->iv, &tx->cipher,
                                       sizeof(rx->iv));
  if (rc != 0)
    return rc;

  rc = tcp2_crypto_rw(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, 0, 0, user_data);
  if (rc != 0)
    return rc;

  LOG("ok");
  return 0;
}

static int tcp2_recv_retry(ngtcp2_conn* conn, const ngtcp2_pkt_hd* hd,
                           void* user_data) {
  LOG("");
  // hd->scid
  // ngtcp2_conn_install_initial_key
  return -1;
}

static int tcp2_recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid,
                                    void* user_data) {
  LOG("");
  Tcp2Key* rx = calloc(1, sizeof(Tcp2Key));
  Tcp2Key* tx = calloc(1, sizeof(Tcp2Key));
  return ngtcp2_conn_install_initial_key(conn, &rx->aead, rx->iv, &rx->cipher,
                                         &tx->aead, tx->iv, &tx->cipher,
                                         sizeof(rx->iv));
}

static int tcp2_recv_crypto_data(ngtcp2_conn* conn,
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
  LOG("");
  memcpy(dest, plaintext, plaintextlen);
  return 0;
}

static int tcp2_decrypt(uint8_t* dest, const ngtcp2_crypto_aead* aead,
                        const ngtcp2_crypto_aead_ctx* aead_ctx,
                        const uint8_t* ciphertext, size_t ciphertextlen,
                        const uint8_t* nonce, size_t noncelen,
                        const uint8_t* aad, size_t aadlen) {
  memcpy(dest, ciphertext, ciphertextlen);
  return 0;
}

static int tcp2_hp_mask(uint8_t* dest, const ngtcp2_crypto_cipher* hp,
                        const ngtcp2_crypto_cipher_ctx* hp_ctx,
                        const uint8_t* sample) {
  LOG("");
  memset(dest, 0, NGTCP2_HP_MASKLEN);
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
                           uint8_t* tx_secret,
                           ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                           ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                           const uint8_t* current_rx_secret,
                           const uint8_t* current_tx_secret, size_t secretlen,
                           void* user_data) {
  LOG("");
  return 0;
}

static void tcp2_delete_crypto_aead_ctx(ngtcp2_conn* conn,
                                        ngtcp2_crypto_aead_ctx* aead_ctx,
                                        void* user_data) {
  LOG("");
}

static void tcp2_delete_crypto_cipher_ctx(ngtcp2_conn* conn,
                                          ngtcp2_crypto_cipher_ctx* cipher_ctx,
                                          void* user_data) {
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
                                    void* user_data) {
  LOG("");

  int rc = 0;
  Tcp2Key* rx = calloc(1, sizeof(Tcp2Key));
  Tcp2Key* tx = calloc(1, sizeof(Tcp2Key));
  rc = ngtcp2_conn_install_vneg_initial_key(conn, version, &rx->aead, rx->iv,
                                            &rx->cipher, &tx->aead, tx->iv,
                                            &tx->cipher, sizeof(rx->iv));
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
  bool zerortt = flags & NGTCP2_STREAM_DATA_FLAG_0RTT;

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
  LOG("");

  // data[offset..offset+datalen] has been acknowledged, can free
  Tcp2Ctx* ctx = user_data;
  (void)ctx;

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
  struct timespec sp;
  clock_gettime(CLOCK_MONOTONIC, &sp);
  return sp.tv_sec * NGTCP2_SECONDS + sp.tv_nsec;
}

static void tcp2_set_callbacks(ngtcp2_callbacks* cb, bool client) {
  // Callback error: NGTCP2_ERR_CALLBACK_FAILURE

  if (client) {
    cb->client_initial = tcp2_client_initial;
    cb->recv_retry = tcp2_recv_retry;
    // Optional
    cb->handshake_confirmed = tcp2_handshake_confirmed;
  } else {
    cb->recv_client_initial = tcp2_recv_client_initial;
  }

  cb->recv_crypto_data = tcp2_recv_crypto_data;
  cb->encrypt = tcp2_encrypt;
  cb->decrypt = tcp2_decrypt;
  cb->hp_mask = tcp2_hp_mask;
  cb->rand = tcp2_rand;
  cb->get_new_connection_id = tcp2_get_new_connection_id;
  cb->update_key = tcp2_update_key;
  cb->delete_crypto_aead_ctx = tcp2_delete_crypto_aead_ctx;
  cb->delete_crypto_cipher_ctx = tcp2_delete_crypto_cipher_ctx;
  cb->get_path_challenge_data = tcp2_get_path_challenge_data;
  cb->version_negotiation = tcp2_version_negotiation;

  // Optional
  cb->recv_stream_data = tcp2_recv_stream_data;
  cb->recv_datagram = tcp2_recv_datagram;
  cb->acked_stream_data_offset = tcp2_acked_stream_data_offset;
  cb->handshake_completed = tcp2_handshake_completed;

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

Tcp2Msg* tcp2_outgoing_dequeue(Tcp2Ctx* ctx) {
  if (ctx->outgoing.head == 0)
    return 0;

  Tcp2Msg* msg = ctx->outgoing.head;
  if (ctx->outgoing.head == ctx->outgoing.tail) {
    ctx->outgoing.head = 0;
    ctx->outgoing.tail = 0;
    return msg;
  }

  ctx->outgoing.head = msg->_next;
  return msg;
}

static int tcp2_outgoing_process(Tcp2Ctx* ctx, Bytes* pkt, u64 now, u64 bytes) {
  if (pkt->len != NGTCP2_MAX_UDP_PAYLOAD_SIZE)
    return -1;

  ngtcp2_ssize stream_write;
  Tcp2Msg* msg = 0;
  bool pkt_full = false;
  u64 maxbytes = ngtcp2_conn_get_send_quantum(ctx->conn);

  while (!pkt_full && bytes < maxbytes && (msg = ctx->outgoing.head)) {
    LOG("!pkt_full, msg len=%d offset=%d", (int)msg->data.len,
        (int)msg->_offset);

    u8* data = msg->data.buf + msg->_offset;
    u64 datalen = msg->data.len - msg->_offset;

    ngtcp2_ssize sz;
    if (msg->stream == TCP2_STREAM_DATAGRAM) {
      ngtcp2_path path = *ngtcp2_conn_get_path(ctx->conn);
      sz = ngtcp2_conn_write_datagram(ctx->conn, &path, 0, pkt->buf, pkt->len,
                                      0, NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0,
                                      data, datalen, now);
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
        // TODO:
        // Need to hang on to this until it's acked
        tcp2_outgoing_dequeue(ctx);
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
  params->initial_max_streams_bidi = 128;
  params->initial_max_streams_uni = 128;
  params->initial_max_stream_data_bidi_local = 128;
  params->initial_max_stream_data_bidi_remote = 128;
  params->initial_max_stream_data_uni = 128;
  params->initial_max_data = 1 << 30;
  params->max_datagram_frame_size = 1024;
}

static int tcp2_connect(ngtcp2_conn** client, const ngtcp2_path* path,
                        const ngtcp2_mem* mem, Tcp2Ctx* ctx, Bytes* pkt,
                        Bytes zerortt_data, u64 now) {
  LOG("");
  ngtcp2_cid scid = {0};
  scid.datalen = TCP2_CIDLEN;
  randombytes_buf(scid.data, scid.datalen);
  ngtcp2_cid dcid = {0};
  dcid.datalen = TCP2_CIDLEN;
  randombytes_buf(dcid.data, dcid.datalen);
  ngtcp2_callbacks callbacks = {0};
  tcp2_set_callbacks(&callbacks, true);
  ngtcp2_transport_params tparams = {0};
  tcp2_transport_params_default(&tparams);
  ngtcp2_settings settings = {0};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now;
  settings.log_printf = tcp2_log_printf;

  int rc = 0;
  LOGB(Bytes(scid.data, scid.datalen));
  rc = ngtcp2_conn_client_new(client, &dcid, &scid, path, NGTCP2_PROTO_VER_V1,
                              &callbacks, &settings, &tparams, mem, ctx);
  if (rc != 0)
    return rc;

  ctx->conn = *client;

  if (zerortt_data.len) {
    if (!ctx->zerortt_params.len)
      return -1;

    LOG("setting 0rtt params");
    rc = ngtcp2_conn_decode_and_set_0rtt_transport_params(
        *client, ctx->zerortt_params.buf, ctx->zerortt_params.len);
    if (rc != 0)
      return rc;
    i64 stream;
    rc = ngtcp2_conn_open_bidi_stream(*client, &stream, ctx);
    if (rc != 0)
      return rc;
    tcp2_outgoing_enqueue(ctx, zerortt_data, stream);
  }

  // Send
  pkt->len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  pkt->buf = malloc(pkt->len);
  rc = tcp2_outgoing_process(ctx, pkt, now, 0);
  if (rc != 0) {
    free(pkt->buf);
    ngtcp2_conn_del(*client);
    return rc;
  }
  return 0;
}

static int tcp2_accept(ngtcp2_conn** server, const ngtcp2_path* path,
                       const ngtcp2_mem* mem, Tcp2Ctx* ctx, Bytes pkt,
                       Bytes* resp, u64 now) {
  LOG("");

  int rc = 0;

  ngtcp2_pkt_hd hd;
  rc = ngtcp2_accept(&hd, pkt.buf, pkt.len);
  if (rc != 0)
    return rc;

  ngtcp2_cid scid = {0};
  scid.datalen = TCP2_CIDLEN;
  randombytes_buf(scid.data, scid.datalen);

  ngtcp2_callbacks callbacks = {0};
  tcp2_set_callbacks(&callbacks, false);
  ngtcp2_transport_params tparams = {0};
  tcp2_transport_params_default(&tparams);
  tparams.original_dcid = hd.dcid;
  tparams.original_dcid_present = 1;
  ngtcp2_settings settings = {0};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now;
  settings.log_printf = tcp2_log_printf;

  LOG("create server version=%d", hd.version);
  rc = ngtcp2_conn_server_new(server, &hd.scid, &scid, path, hd.version,
                              &callbacks, &settings, &tparams, mem, ctx);
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
  resp->len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  resp->buf = malloc(resp->len);
  rc = tcp2_outgoing_process(ctx, resp, now, 0);
  if (rc != 0) {
    free(resp->buf);
    ngtcp2_conn_del(*server);
    return rc;
  }
  return 0;
}

static ngtcp2_addr tcp2_ipv4(const char* host, u16 port,
                             ngtcp2_sockaddr_union* addru) {
  ngtcp2_addr addr = {&addru->sa, sizeof(addru->in)};
  addru->in.sin_family = AF_INET;
  addru->in.sin_port = port;
  inet_aton(host, &addru->in.sin_addr);
  return addr;
}

static int demo_tcp2(int argc, const char** argv) {
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
  ngtcp2_addr server_addr = tcp2_ipv4(TCP2_LOCALHOST, 3333, &server_addru);

  const ngtcp2_mem* mem = ngtcp2_mem_default();

  u64 now = tcp2_current_time();

  // Client connect
  Tcp2Ctx client_ctx = {0};
  ngtcp2_conn* client;
  Bytes pkt_connect;
  ngtcp2_path client_path = {.local = client_addr, .remote = server_addr};
  CHECK_TCP2(tcp2_connect(&client, &client_path, mem, &client_ctx, &pkt_connect,
                          BytesZero, now));

  // Server reply
  now = tcp2_current_time();
  Tcp2Ctx server_ctx = {0};
  ngtcp2_conn* server;
  Bytes pkt_connect_reply;
  ngtcp2_path server_path = {.local = server_addr, .remote = client_addr};
  LOG("receiving packet");
  CHECK_TCP2(tcp2_accept(&server, &server_path, mem, &server_ctx, pkt_connect,
                         &pkt_connect_reply, now));
  free(pkt_connect.buf);

  // Client finish and send data
  now = tcp2_current_time();
  Bytes msg;
  msg.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  msg.buf = malloc(msg.len);
  LOG("client receiving packet");
  CHECK_TCP2(ngtcp2_conn_read_pkt(client, &client_path, 0,
                                  pkt_connect_reply.buf, pkt_connect_reply.len,
                                  now));
  LOG("client send some data");
  i64 stream;
  {
    CHECK_TCP2(ngtcp2_conn_open_bidi_stream(client, &stream, &client_ctx));
    tcp2_outgoing_enqueue(&client_ctx, Str("hi from client"), stream);
    CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg, now, 0));
  }
  free(pkt_connect_reply.buf);

  // Server data receive
  now = tcp2_current_time();
  Bytes msg2;
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  msg2.buf = malloc(msg.len);
  LOG("server receiving msg");
  CHECK_TCP2(
      ngtcp2_conn_read_pkt(server, &server_path, 0, msg.buf, msg.len, now));
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
  free(msg.buf);

  LOG("client receiving packet");
  now = tcp2_current_time();
  CHECK_TCP2(
      ngtcp2_conn_read_pkt(client, &client_path, 0, msg2.buf, msg2.len, now));

  // Let's try a connection migration
  now = tcp2_current_time();
  ngtcp2_sockaddr_union client_addru_new;
  ngtcp2_addr client_addr_new =
      tcp2_ipv4(TCP2_LOCALHOST, 2223, &client_addru_new);
  ngtcp2_path client_path_new = {.local = client_addr_new,
                                 .remote = server_addr};
  ngtcp2_path server_path_new = {.local = server_addr,
                                 .remote = client_addr_new};
  CHECK_TCP2(ngtcp2_conn_initiate_migration(client, &client_path_new, now));
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&client_ctx, &msg2, now, 0));

  for (int i = 0; i < 5; ++i) {
    if (msg2.len) {
      // Server recv
      now = tcp2_current_time();
      CHECK_TCP2(ngtcp2_conn_read_pkt(server, &server_path_new, 0, msg2.buf,
                                      msg2.len, now));
      msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));
    } else
      LOG("skip");

    if (msg2.len) {
      // Client recv
      now = tcp2_current_time();
      CHECK_TCP2(ngtcp2_conn_read_pkt(client, &client_path_new, 0, msg2.buf,
                                      msg2.len, now));
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
  now = tcp2_current_time();
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  CHECK_TCP2(tcp2_outgoing_process(&server_ctx, &msg2, now, 0));

  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path_new, 0,
                                  msg2.buf, msg2.len, now));

  // Close the connection
  now = tcp2_current_time();
  msg2.len = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
  ngtcp2_ccerr ccerr = {0};
  ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;
  ngtcp2_ssize sz = ngtcp2_conn_write_connection_close(
      client_ctx.conn, &client_path_new, 0, msg2.buf, msg2.len, &ccerr, now);
  CHECK_TCP2(sz);
  msg2.len = sz;

  now = tcp2_current_time();
  CHECK(ngtcp2_conn_read_pkt(server_ctx.conn, &server_path_new, 0, msg2.buf,
                             msg2.len, now) == NGTCP2_ERR_DRAINING);

  // Cleanup

  allocator_free(client_ctx.allocator, msg2);

  ngtcp2_conn_del(client_ctx.conn);
  ngtcp2_conn_del(server_ctx.conn);

  tcp2_sent_free(&client_ctx);
  tcp2_sent_free(&server_ctx);

  tcp2_outgoing_free(&client_ctx);
  tcp2_outgoing_free(&server_ctx);

  // Attempt a 0-RTT data send
  LOG("0rtt send");
  now = tcp2_current_time();
  CHECK_TCP2(
      tcp2_connect(&client_ctx, &client_path, &pkt_connect, Str("zero!"), now));
  LOG("0rtt recv");
  now = tcp2_current_time();
  CHECK_TCP2(tcp2_accept(&server_ctx, &server_path, pkt_connect,
                         &pkt_connect_reply, now));
  LOG("0rtt reply");
  now = tcp2_current_time();
  CHECK_TCP2(ngtcp2_conn_read_pkt(client_ctx.conn, &client_path, 0,
                                  pkt_connect_reply.buf, pkt_connect_reply.len,
                                  now));

  allocator_free(client_ctx.allocator, pkt_connect);
  allocator_free(server_ctx.allocator, pkt_connect_reply);

  ngtcp2_conn_del(client_ctx.conn);
  ngtcp2_conn_del(server_ctx.conn);

  tcp2_sent_free(&client_ctx);
  tcp2_sent_free(&server_ctx);
  tcp2_outgoing_free(&client_ctx);
  tcp2_outgoing_free(&server_ctx);

  hashmap_deinit(&client_ctx.sent);
  hashmap_deinit(&server_ctx.sent);

  return 0;
}

static int demo_containers(int argc, const char** argv) {
  Allocator al = allocatormi_allocator();
  {
    List a;
    List_init(&a, i32, al, 16);

    i32* a0 = list_get(&a, 0);
    CHECK0(a0);

    i32* an;
    CHECK0(list_addn(&a, 8, (void**)&an));
    for (i32 i = 0; i < 8; ++i) {
      an[i] = i + 22;
    }

    for (i32 i = 0; i < 8; ++i) {
      CHECK(*(i32*)list_get(&a, i) == i + 22);
    }

    CHECK0(list_addn(&a, 16, (void**)&an));

    i32 x = 7;
    list_set(&a, 22, &x);
    CHECK(*(i32*)list_get(&a, 22) == 7);

    list_deinit(&a);
  }

  {
    Hashmap a;
    CHECK0(Hashmap_i32_create(&a, i32, al));
    CHECK0(a.n_buckets);

    {
      i32* x;
      i32* y;
      hashmap_foreach(&a, x, y, { CHECK((*x + *y) == 10); });
    }

    {
      i32 x = 0;
      HashmapStatus s;
      HashmapIter it = hashmap_put(&a, &x, &s);
      CHECK(it != hashmap_end(&a));
      CHECK(s == HashmapStatus_New);
      CHECK(a.n_buckets == 4);
      *(i32*)hashmap_val(&a, it) = 10;
    }

    for (i32 i = 1; i < 10; ++i) {
      HashmapStatus s;
      HashmapIter it = hashmap_put(&a, &i, &s);
      CHECK(it != hashmap_end(&a));
      CHECK(s == HashmapStatus_New);
      *(i32*)hashmap_val(&a, it) = 10 - i;
    }

    {
      i32 n = 0;
      i32* x;
      i32* y;
      hashmap_foreach(&a, x, y, {
        CHECK((*x + *y) == 10);
        ++n;
      });
      CHECK(n == 10);
    }

    hashmap_deinit(&a);
  }

  {
    typedef struct {
      i64 x;
      Node n;
    } A;

    Queue q = {0};

    A vals[8] = {0};
    for (usize i = 0; i < ARRAY_LEN(vals); ++i) {
      vals[i].x = i + 22;
      q_enq(&q, &vals[i].n);
    }

    Node* n;
    i64 i = 0;
    while ((n = q_deq(&q))) {
      CHECK(CONTAINER_OF(n, A, n)->x == i + 22);
      ++i;
    }
  }

  return 0;
}

static const char* const usages[] = {
    "pk [options] [cmd] [args]\n\n    Commands:"
    "\n      - demo-b58"
    "\n      - demo-base64"
    "\n      - demo-bip39"
    "\n      - demo-drat"
    "\n      - demo-holepunch"
    "\n      - demo-keygen"
    "\n      - demo-keyread"
    "\n      - demo-kv"
    "\n      - demo-mimalloc"
    "\n      - demo-multicast"
    "\n      - demo-nik"
    "\n      - demo-nikcxn"
    "\n      - demo-pwhash"
    "\n      - demo-sshkeyread"
    "\n      - demo-vterm"
    "\n      - demo-x3dh"
    "\n      - demo-tcp2"
    "\n      - demo-containers"
    //
    ,
    NULL,
};

struct cmd_struct {
  const char* cmd;
  int (*fn)(int, const char**);
};

static struct cmd_struct commands[] = {
    {"demo-b58", demo_b58},                //
    {"demo-base64", demo_base64},          //
    {"demo-bip39", demo_bip39},            //
    {"demo-drat", demo_drat},              //
    {"demo-holepunch", demo_holepunch},    //
    {"demo-keygen", demo_keygen},          //
    {"demo-keyread", demo_keyread},        //
    {"demo-kv", demo_kv},                  //
    {"demo-mimalloc", demo_mimalloc},      //
    {"demo-multicast", demo_multicast},    //
    {"demo-nik", demo_nik},                //
    {"demo-nikcxn", demo_nikcxn},          //
    {"demo-pwhash", demo_pwhash},          //
    {"demo-sshkeyread", demosshkeyread},   //
    {"demo-vterm", demo_vterm},            //
    {"demo-x3dh", demo_x3dh},              //
    {"demo-tcp2", demo_tcp2},              //
    {"demo-containers", demo_containers},  //
};

typedef struct {
  int argc;
  const char** argv;
} MainCoroCtx;

static void coro_exit(int code) { mco_push(mco_running(), &code, 1); }

static void main_coro(mco_coro* co) {
  MainCoroCtx* ctx = (MainCoroCtx*)mco_get_user_data(co);

  int argc = ctx->argc;
  const char** argv = ctx->argv;

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

  struct cmd_struct* cmd = NULL;
  for (usize i = 0; i < ARRAY_LEN(commands); i++) {
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

#define MAIN_STACK_SIZE 1 << 21  // 2MiB
u8 main_stack[MAIN_STACK_SIZE];

static void* mco_alloc(size_t size, void* udata) {
  return calloc(1, size);
  // return CBASE_ALIGN(main_stack, 1 << 12);
}

static void mco_dealloc(void* ptr, size_t size, void* udata) {}

int main(int argc, const char** argv) {
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
  mco_coro* co;
  CHECK(mco_create(&co, &desc) == MCO_SUCCESS);

  // run
  CHECK(mco_resume(co) == MCO_SUCCESS);
  if (mco_status(co) == MCO_SUSPENDED) {
    uv_run(loop, UV_RUN_DEFAULT);
  }
  LOG("uv loop done");

  int rc = 0;
  if (mco_get_storage_size(co) > 0)
    mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  uv_loop_close(loop);
  free(loop);

  if (rc == 0)
    LOG("goodbye");
  else
    LOG("ERROR code=%d", rc);
  return rc;
}
