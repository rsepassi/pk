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
#include "keyio.h"
#include "log.h"
#include "nik.h"
#include "nik_cxn.h"
#include "signal.h"
#include "stdmacros.h"
#include "stdtypes.h"
#include "taia.h"
#include "uvco.h"

#define MAX_PW_LEN 2048

#define NS_PER_MS 1000000ULL
#define MS_PER_SEC 1000ULL

#define PK_SK_HEADER "-----BEGIN PK PRIVATE KEY-----\n"
#define PK_SK_FOOTER "\n-----END PK PRIVATE KEY-----\n"
#define PK_SKP_HEADER "-----BEGIN PROTECTED PK PRIVATE KEY-----\n"
#define PK_SKP_FOOTER "\n-----END PROTECTED PK PRIVATE KEY-----\n"

// Global event loop
uv_loop_t* loop;

// Some constant data
char* A_to_B_message = "hello world";
char* A_seed_hex =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char* B_seed_hex =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

void bytes_from_hex(Str s, u8* out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char*)s.buf, s.len, 0, 0, 0);
}

// Printing
void phex(char* tag, u8* b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i)
    printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8*)&(k), sizeof(k))

int nik_keys_kx_from_seed(const CryptoSeed* seed, CryptoKxKeypair* out) {
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

void CxnCb(NIK_Cxn* cxn, void* userdata, NIK_Cxn_Event e, Bytes data, u64 now) {
  LOGS(data);
}

int demo_nikcxn(int argc, const char** argv) {
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

int demo_nik(int argc, const char** argv) {
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

int cryptkv_keycrypt(CryptKv* kv, Bytes key, Bytes* out) {
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

int cryptkv_put(CryptKv* kv, Bytes key, Bytes val) {
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

int cryptkv_get(CryptKv* kv, Bytes key, Bytes* val) {
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

int cryptkv_open(CryptKv** kv_ptr, const char* kv_path, CryptoBoxKey* key,
                 Allocator allocator) {
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

void cryptkv_close(CryptKv* kv) {
  mdb_env_close(kv->kv);
  sodium_memzero(kv, sizeof(CryptKv));
  sodium_free(kv);
}

int demo_kv(int argc, const char** argv) {
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

int demosshkeyread(int argc, const char** argv) {
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

int demo_bip39(int argc, const char** argv) {
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

int demo_base64(int argc, const char** argv) {
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

void vt_cb(const char* s, size_t len, void* user) {
  LOG("vt(%d)=%.*s", (int)len, (int)len, s);
}

int demo_vterm(int argc, const char** argv) {
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

void get_identity_key(Str hex, CryptoSignSK* out) {
  CHECK(hex.len == 64, "got length %d", (int)hex.len);
  CryptoSeed seed;
  sodium_hex2bin((u8*)&seed, sizeof(CryptoSeed), (char*)hex.buf, hex.len, 0, 0,
                 0);

  CryptoSignPK pk;
  CHECK0(crypto_sign_seed_keypair((u8*)&pk, (u8*)out, (u8*)&seed));
}

int drat_a_to_b(DratState* A_state, X3DH* A_x, DratState* B_state, X3DH* B_x,
                Str msg) {
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

int demo_drat(int argc, const char** argv) {
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

int demo_x3dh(int argc, const char** argv) {
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

int demo_getkey(Str seed_str, CryptoSignPK* pk, CryptoSignSK* sk) {
  CryptoSeed seed;
  sodium_hex2bin((u8*)&seed, sizeof(seed), (char*)seed_str.buf, seed_str.len, 0,
                 0, 0);
  if (crypto_sign_seed_keypair((u8*)pk, (u8*)sk, (u8*)&seed))
    return 1;
  return 0;
}

bool libb58_sha256_impl(void* out, const void* msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}

int demo_b58(int argc, const char** argv) {
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

void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  *buf = uv_buf_init(malloc(suggested_size), (uint)suggested_size);
}

void recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
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

void mapping_callback(int id, plum_state_t state,
                      const plum_mapping_t* mapping) {
  LOG("map!");
  CHECK(state == PLUM_STATE_SUCCESS);
  LOG("External address: %s:%hu\n", mapping->external_host,
      mapping->external_port);
}

int demo_multicast(int argc, const char** argv) {
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
    uv_buf_t buf = uv_buf_init((char*)peer_id.buf, (uint)peer_id.len);
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

int demo_holepunch(int argc, const char** argv) {
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
  uv_buf_t buf = uv_buf_init((char*)peer_id.buf, (uint)peer_id.len);
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

void do_some_allocs(Allocator a) {
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

int demo_mimalloc(int argc, const char** argv) {
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

int pw_prompt(Bytes* b) {
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

int demo_keyread(int argc, const char** argv) {
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

int demo_keygen(int argc, const char** argv) {
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

int demo_pwhash(int argc, const char** argv) {
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

typedef struct {
  void* x;
} Tcp2Ctx;

int tcp2_client_initial(ngtcp2_conn* conn, void* user_data) {
  LOG("");
  // ngtcp2_conn_install_initial_key
  // ngtcp2_conn_submit_crypto_data
  return 0;
}

int tcp2_recv_retry(ngtcp2_conn* conn, const ngtcp2_pkt_hd* hd,
                    void* user_data) {
  LOG("");
  // hd->scid
  // ngtcp2_conn_install_initial_key
  return 0;
}

int tcp2_recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid,
                             void* user_data) {
  LOG("");
  // ngtcp2_conn_install_initial_key
  return 0;
}

int tcp2_recv_crypto_data(ngtcp2_conn* conn,
                          ngtcp2_encryption_level encryption_level,
                          uint64_t offset, const uint8_t* data, size_t datalen,
                          void* user_data) {
  LOG("");
  // ngtcp2_crypto_derive_and_install_rx_key
  // ngtcp2_crypto_derive_and_install_tx_key
  // ngtcp2_conn_submit_crypto_data
  return 0;
}

int tcp2_encrypt(uint8_t* dest, const ngtcp2_crypto_aead* aead,
                 const ngtcp2_crypto_aead_ctx* aead_ctx,
                 const uint8_t* plaintext, size_t plaintextlen,
                 const uint8_t* nonce, size_t noncelen, const uint8_t* aad,
                 size_t aadlen) {
  LOG("");
  return 0;
}

int tcp2_decrypt(uint8_t* dest, const ngtcp2_crypto_aead* aead,
                 const ngtcp2_crypto_aead_ctx* aead_ctx,
                 const uint8_t* ciphertext, size_t ciphertextlen,
                 const uint8_t* nonce, size_t noncelen, const uint8_t* aad,
                 size_t aadlen) {
  LOG("");
  return 0;
}

int tcp2_hp_mask(uint8_t* dest, const ngtcp2_crypto_cipher* hp,
                 const ngtcp2_crypto_cipher_ctx* hp_ctx,
                 const uint8_t* sample) {
  LOG("");
  return 0;
}

void tcp2_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
  (void)rand_ctx;
  randombytes_buf(dest, destlen);
}

int tcp2_get_new_connection_id(ngtcp2_conn* conn, ngtcp2_cid* cid,
                               uint8_t* token, size_t cidlen, void* user_data) {
  LOG("");
  return 0;
}

int tcp2_update_key(ngtcp2_conn* conn, uint8_t* rx_secret, uint8_t* tx_secret,
                    ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                    ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                    const uint8_t* current_rx_secret,
                    const uint8_t* current_tx_secret, size_t secretlen,
                    void* user_data) {
  LOG("");
  return 0;
}

void tcp2_delete_crypto_aead_ctx(ngtcp2_conn* conn,
                                 ngtcp2_crypto_aead_ctx* aead_ctx,
                                 void* user_data) {
  LOG("");
}

void tcp2_delete_crypto_cipher_ctx(ngtcp2_conn* conn,
                                   ngtcp2_crypto_cipher_ctx* cipher_ctx,
                                   void* user_data) {
  LOG("");
}

int tcp2_get_path_challenge_data(ngtcp2_conn* conn, uint8_t* data,
                                 void* user_data) {
  LOG("");
  return 0;
}

int tcp2_version_negotiation(ngtcp2_conn* conn, uint32_t version,
                             const ngtcp2_cid* client_dcid, void* user_data) {
  LOG("");
  // ngtcp2_conn_install_vneg_initial_key
  return 0;
}

void tcp2_log_printf(void* user_data, const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

u64 tcp2_current_time() {
  struct timespec sp;
  clock_gettime(CLOCK_MONOTONIC, &sp);
  return sp.tv_sec * NGTCP2_SECONDS + sp.tv_nsec;
}

void tcp2_set_callbacks(ngtcp2_callbacks* cb, bool client) {
  if (client) {
    cb->client_initial = tcp2_client_initial;
    cb->recv_retry = tcp2_recv_retry;
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

  // Callback error: NGTCP2_ERR_CALLBACK_FAILURE

  // Optional
  // ngtcp2_handshake_completed handshake_completed;
  // ngtcp2_recv_version_negotiation recv_version_negotiation;
  // ngtcp2_recv_stream_data recv_stream_data;
  // ngtcp2_acked_stream_data_offset acked_stream_data_offset;
  // ngtcp2_stream_open stream_open;
  // ngtcp2_stream_close stream_close;
  // ngtcp2_recv_stateless_reset recv_stateless_reset;
  // ngtcp2_extend_max_streams extend_max_local_streams_bidi;
  // ngtcp2_extend_max_streams extend_max_local_streams_uni;
  // ngtcp2_remove_connection_id remove_connection_id;
  // ngtcp2_path_validation path_validation;
  // ngtcp2_select_preferred_addr select_preferred_addr;
  // ngtcp2_stream_reset stream_reset;
  // ngtcp2_extend_max_streams extend_max_remote_streams_bidi;
  // ngtcp2_extend_max_streams extend_max_remote_streams_uni;
  // ngtcp2_extend_max_stream_data extend_max_stream_data;
  // ngtcp2_connection_id_status dcid_status;
  // ngtcp2_handshake_confirmed handshake_confirmed;
  // ngtcp2_recv_new_token recv_new_token;
  // ngtcp2_recv_datagram recv_datagram;
  // ngtcp2_ack_datagram ack_datagram;
  // ngtcp2_lost_datagram lost_datagram;
  // ngtcp2_stream_stop_sending stream_stop_sending;
  // ngtcp2_recv_key recv_rx_key;
  // ngtcp2_recv_key recv_tx_key;
  // ngtcp2_tls_early_data_rejected tls_early_data_rejected;
}

int demo_tcp2(int argc, const char** argv) {
  LOG("tcp2");

  // https://nghttp2.org/ngtcp2/programmers-guide.html

  // Send
  // ngtcp2_conn_open_bidi_stream()
  // ngtcp2_conn_open_uni_stream()
  // ngtcp2_conn_writev_stream() or ngtcp2_conn_write_pkt()
  // ngtcp2_settings.max_tx_udp_payload_size byte packets (1200)
  //
  // Cannot open a stream until handshake completed
  // extend_max_local_streams{uni,bidi} also indicate streams are open
  //
  // An application should pace sending packets. ngtcp2_conn_get_send_quantum()
  // returns the number of bytes that can be sent without packet spacing. After
  // one or more calls of ngtcp2_conn_writev_stream() (it can be called
  // multiple times to fill the buffer sized up to
  // ngtcp2_conn_get_send_quantum() bytes), call
  // ngtcp2_conn_update_pkt_tx_time() to set the timer when the next packet
  // should be sent. The timer is integrated into ngtcp2_conn_get_expiry().

  // Recv
  // ngtcp2_pkt_decode_version_cid()
  // If NGTCP2_ERR_VERSION_NEGOTIATION, ngtcp2_pkt_write_version_negotiation()
  // If existing conn id, ngtcp2_conn_read_pkt()
  // Otherwise, ngtcp2_accept() then ngtcp2_conn_read_pkt()

  // Timers
  // ngtcp2_conn_get_expiry
  // Call ngtcp2_conn_handle_expiry() upon expiry
  //   And then ngtcp2_conn_writev_stream() (or ngtcp2_conn_writev_datagram()
  // If it returns NGTCP2_ERR_IDLE_CLOSE, drop connection without calling write

  // 0rtt
  //   ngtcp2_conn_encode_0rtt_transport_params
  //   ngtcp2_conn_decode_and_set_0rtt_transport_params
  //   ngtcp2_conn_decode_and_set_remote_transport_params
  //   ngtcp2_conn_tls_early_data_rejected
  // Connection migration
  //   ngtcp2_conn_initiate_migration

  // Other
  // ngtcp2_conn_initiate_key_update
  // ngtcp2_conn_install_0rtt_key
  // ngtcp2_conn_install_initial_key
  // ngtcp2_conn_install_rx_handshake_key
  // ngtcp2_conn_install_rx_key
  // ngtcp2_conn_install_tx_handshake_key
  // ngtcp2_conn_install_tx_key
  // ngtcp2_conn_install_vneg_initial_key
  // ngtcp2_conn_set_0rtt_crypto_ctx
  // ngtcp2_conn_set_crypto_ctx
  // ngtcp2_conn_set_initial_crypto_ctx
  // ngtcp2_conn_set_keep_alive_timeout
  // ngtcp2_conn_set_local_addr
  // ngtcp2_conn_set_local_transport_params
  // ngtcp2_conn_set_path_user_data
  // ngtcp2_conn_set_retry_aead
  // ngtcp2_conn_set_stream_user_data
  // ngtcp2_conn_set_tls_alert
  // ngtcp2_conn_set_tls_error
  // ngtcp2_conn_set_tls_native_handle
  // ngtcp2_conn_submit_crypto_data
  // ngtcp2_conn_submit_new_token
  // ngtcp2_conn_tls_handshake_completed
  // ngtcp2_conn_update_pkt_tx_time

  ngtcp2_cid client_cid = {0};
  client_cid.datalen = 8;
  randombytes_buf(client_cid.data, client_cid.datalen);

  uint32_t client_version = NGTCP2_PROTO_VER_V1;

  ngtcp2_sockaddr_union client_addru;
  client_addru.in.sin_family = AF_INET;
  client_addru.in.sin_port = 2222;
  inet_aton("127.0.0.1", &client_addru.in.sin_addr);
  ngtcp2_sockaddr_union server_addru;
  server_addru.in.sin_family = AF_INET;
  server_addru.in.sin_port = 3333;
  inet_aton("127.0.0.1", &server_addru.in.sin_addr);

  ngtcp2_addr client_addr = {&client_addru.sa, sizeof(client_addru.in)};
  ngtcp2_addr server_addr = {&server_addru.sa, sizeof(server_addru.in)};

  ngtcp2_settings settings = {0};
  ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION, &settings);
  settings.initial_ts = tcp2_current_time();
  settings.log_printf = tcp2_log_printf;

  const ngtcp2_mem* mem = ngtcp2_mem_default();

  ngtcp2_cid dcid = {0};
  dcid.datalen = 8;
  randombytes_buf(dcid.data, dcid.datalen);

  Tcp2Ctx client_ctx = {0};
  ngtcp2_conn* client;
  {
    ngtcp2_path path = {.local = client_addr, .remote = server_addr};
    ngtcp2_callbacks callbacks = {0};
    tcp2_set_callbacks(&callbacks, true);
    ngtcp2_transport_params tparams = {0};
    ngtcp2_transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_VERSION,
                                              &tparams);

    LOG("create client");
    CHECK0(ngtcp2_conn_client_new_versioned(
        &client, &dcid, &client_cid, &path, client_version,
        NGTCP2_CALLBACKS_VERSION, &callbacks, NGTCP2_SETTINGS_VERSION,
        &settings, NGTCP2_TRANSPORT_PARAMS_VERSION, &tparams, mem,
        &client_ctx));
  }

  Tcp2Ctx server_ctx = {0};
  ngtcp2_conn* server;
  {
    ngtcp2_cid scid = {0};
    scid.datalen = 8;
    randombytes_buf(scid.data, scid.datalen);

    ngtcp2_path path = {.local = server_addr, .remote = client_addr};
    ngtcp2_callbacks callbacks = {0};
    tcp2_set_callbacks(&callbacks, false);
    ngtcp2_transport_params tparams = {0};
    ngtcp2_transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_VERSION,
                                              &tparams);
    tparams.original_dcid = dcid;
    tparams.original_dcid_present = 1;

    LOG("create server");
    CHECK0(ngtcp2_conn_server_new_versioned(
        &server, &client_cid, &scid, &path, client_version,
        NGTCP2_CALLBACKS_VERSION, &callbacks, NGTCP2_SETTINGS_VERSION,
        &settings, NGTCP2_TRANSPORT_PARAMS_VERSION, &tparams, mem,
        &server_ctx));
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
    //
    ,
    NULL,
};

struct cmd_struct {
  const char* cmd;
  int (*fn)(int, const char**);
};

static struct cmd_struct commands[] = {
    {"demo-b58", demo_b58},               //
    {"demo-base64", demo_base64},         //
    {"demo-bip39", demo_bip39},           //
    {"demo-drat", demo_drat},             //
    {"demo-holepunch", demo_holepunch},   //
    {"demo-keygen", demo_keygen},         //
    {"demo-keyread", demo_keyread},       //
    {"demo-kv", demo_kv},                 //
    {"demo-mimalloc", demo_mimalloc},     //
    {"demo-multicast", demo_multicast},   //
    {"demo-nik", demo_nik},               //
    {"demo-nikcxn", demo_nikcxn},         //
    {"demo-pwhash", demo_pwhash},         //
    {"demo-sshkeyread", demosshkeyread},  //
    {"demo-vterm", demo_vterm},           //
    {"demo-x3dh", demo_x3dh},             //
    {"demo-tcp2", demo_tcp2},             //
};

typedef struct {
  int argc;
  const char** argv;
} MainCoroCtx;

void coro_exit(int code) { mco_push(mco_running(), &code, 1); }

void main_coro(mco_coro* co) {
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

void* mco_alloc(size_t size, void* udata) {
  return calloc(1, size);
  // return CBASE_ALIGN(main_stack, 1 << 12);
}

void mco_dealloc(void* ptr, size_t size, void* udata) {}

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
