#define _POSIX_C_SOURCE 200809L

#include "cli.h"

// vendor deps
#include "libbase58.h"
#include "lmdb.h"
#include "mimalloc.h"
#include "minicoro.h"
#include "ngtcp2/ngtcp2.h"
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

// Defined in pk.c
int pk_main(int argc, char** argv);
// Defined in echo.c
int demo_echo(int argc, char** argv);

// Global event loop
uv_loop_t* loop;

// Some constant data
char* A_to_B_message = "hello world";
char* A_seed_hex =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char* B_seed_hex =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

// Printing
static void phex(char* tag, u8* b, u64 len) {
  printf("%s(%" PRIu64 ")=", tag, len);
  for (u64 i = 0; i < len; ++i)
    printf("%02X", b[i]);
  printf("\n");
}

#define pcrypt(k) phex(#k, (u8*)&(k), sizeof(k))

static int nik_keys_kx_from_seed(const CryptoSignSeed* seed,
                                 CryptoKxKeypair*      out) {
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

static int demo_nikcxn(int argc, char** argv) {
  CryptoKxKeypair kx_keys_i;
  {
    Str            A_seed_str = str_from_c(A_seed_hex);
    CryptoSignSeed A_seed;
    sodium_hex2bin((u8*)&A_seed, sizeof(A_seed), (char*)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &kx_keys_i));
  }

  CryptoKxKeypair kx_keys_r;
  {
    Str            B_seed_str = str_from_c(B_seed_hex);
    CryptoSignSeed B_seed;
    sodium_hex2bin((u8*)&B_seed, sizeof(B_seed), (char*)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &kx_keys_r));
  }

  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk, 0};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk, 0};

  NIK_Cxn cxn_A;
  u64     ctx_A;
  NIK_Cxn cxn_B;
  u64     ctx_B;
  LOG("cxn_A=%p", &cxn_A);
  LOG("cxn_B=%p", &cxn_B);

  Bytes zero     = BytesZero;
  u64   maxdelay = UINT64_MAX;
  u64   now      = 1;

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
    NIK_Handshake      hs;
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
    u64      delay_A   = cxn_A.handshake.initiator.handshake_start_time;
    u64      delay_B   = cxn_B.handshake.initiator.handshake_start_time;
    u64      delay     = MIN(delay_A, delay_B);
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

static int demo_nik(int argc, char** argv) {
  CryptoKxKeypair kx_keys_i;
  {
    Str            A_seed_str = str_from_c(A_seed_hex);
    CryptoSignSeed A_seed;
    sodium_hex2bin((u8*)&A_seed, sizeof(A_seed), (char*)A_seed_str.buf,
                   A_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&A_seed, &kx_keys_i));
  }

  CryptoKxKeypair kx_keys_r;
  {
    Str            B_seed_str = str_from_c(B_seed_hex);
    CryptoSignSeed B_seed;
    sodium_hex2bin((u8*)&B_seed, sizeof(B_seed), (char*)B_seed_str.buf,
                   B_seed_str.len, 0, 0, 0);
    CHECK0(nik_keys_kx_from_seed(&B_seed, &kx_keys_r));
  }

  u32      id_i    = 1;
  u32      id_r    = 2;
  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk, 0};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk, 0};

  // I
  LOG("i2r");
  NIK_Handshake     state_i;
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
    send_msg    = (Str){.len = send_sz, .buf = malloc(send_sz)};
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
    send_msg    = (Str){.len = send_sz, .buf = malloc(send_sz)};
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
  MDB_env*     kv;
  MDB_dbi      db;
  CryptoBoxKey key;
  Allocator    allocator;
} CryptKv;

static int cryptkv_keycrypt(CryptKv* kv, Bytes key, Bytes* out) {
  // Encrypt the key with a nonce derived from the key
  int rc       = 1;
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
  *kv_ptr     = sodium_malloc(sizeof(CryptKv));
  CryptKv* kv = *kv_ptr;
  *kv         = (CryptKv){0};

  kv->key       = *key;
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

static int demo_kv(int argc, char** argv) {
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

  Allocator    allocator = allocator_libc();
  CryptoBoxKey kvkey     = {{1, 2, 3, 4}};

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

static int demosshkeyread(int argc, char** argv) {
  CHECK(argc == 2, "must provide a key path");
  const char* path = argv[1];

  u8    str_buf[1024];
  Bytes str = BytesArray(str_buf);  // SECRET

  uv_file fd;
  CHECK0(uvco_fs_open(loop, path, UV_FS_O_RDONLY, 0, &fd));
  CHECK0(uvco_fs_read(loop, fd, &str, 0));
  uvco_fs_close(loop, fd);
  LOG("read %d", (int)str.len);
  CHECK(str.len < 1024);

  CryptoSignSK sk;
  CHECK0(keyio_keydecode_openssh(str, &sk));
  LOGB(CryptoBytes(sk));

  return 0;
}

static void vt_cb(const char* s, size_t len, void* user) {
  LOG("vt(%d)=%.*s", (int)len, (int)len, s);
}

static int demo_vterm(int argc, char** argv) {
  int    rows = 100;
  int    cols = 80;
  VTerm* vt   = vterm_new(rows, cols);
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

static int demo_multicast(int argc, char** argv) {
  bool send = argc > 1 && memcmp(argv[1], "send", 4) == 0;

  LOG("udp init");
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  char* multicast_group = "239.0.0.22";
  int   port            = 20000;

  if (send) {
    struct sockaddr_in myaddr;
    CHECK0(uv_ip4_addr("0.0.0.0", 0, &myaddr));
    CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));

    struct sockaddr_storage localbind;
    int                     len;
    CHECK0(uv_udp_getsockname(&udp, (struct sockaddr*)&localbind, &len));
    LOG("addrlen=%d", len);
    // LOG("addr=%u", ((struct sockaddr_in*)&localbind)->sin_addr.s_addr);

    LOG("udp send");
    struct sockaddr_in multi_addr;
    CHECK0(uv_ip4_addr(multicast_group, port, &multi_addr));
    Str      peer_id = Str("mike multicast");
    uv_buf_t buf     = uv_buf_init((char*)peer_id.buf, (int)peer_id.len);
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

#ifndef PK_PLUM_DISABLED
#include "plum/plum.h"
static void mapping_callback(int id, plum_state_t state,
                             const plum_mapping_t* mapping) {
  LOG("map!");
  CHECK(state == PLUM_STATE_SUCCESS);
  LOG("External address: %s:%hu\n", mapping->external_host,
      mapping->external_port);
}

static int demo_holepunch(int argc, char** argv) {
  // TODO:
  // Hit discovery server to get peer_addr

  // Hard-coding for now
  struct sockaddr_in peer_addr;
  CHECK0(uv_ip4_addr("75.164.165.93", 8087, &peer_addr));

  // Plum
  plum_config_t config = {0};
  config.log_level     = PLUM_LOG_LEVEL_WARN;
  plum_init(&config);
  plum_mapping_t mapping = {0};
  mapping.protocol       = PLUM_IP_PROTOCOL_UDP;
  mapping.internal_port  = 20000;
  int mapping_id         = plum_create_mapping(&mapping, mapping_callback);
  struct sockaddr_in myaddr;
  CHECK0(uv_ip4_addr("0.0.0.0", 20000, &myaddr));

  LOG("udp init");
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  LOG("udp send");
  Str      peer_id = Str("mike multicast");
  uv_buf_t buf     = uv_buf_init((char*)peer_id.buf, (int)peer_id.len);
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
#else
static int demo_holepunch(int argc, char** argv) {
  CHECK(false, "disabled");
  return 0;
}
#endif  // PK_PLUM_DISABLED

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

static int demo_mimalloc(int argc, char** argv) {
  // MIMALLOC_SHOW_STATS=1
  mi_option_enable(mi_option_show_stats);

  Allocator a1 = allocatormi_allocator();
  do_some_allocs(a1);

  Allocator a2 = allocatormi_allocator();
  do_some_allocs(a2);

  // {
  //   Bytes x = allocatormi_block_alloc(1);
  //   Allocator a3 = allocatormi_arena(x, true);
  //   do_some_allocs(a3);
  //   allocatormi_block_free(x);
  // }

  {
    Bytes         x = {1024, malloc(1024)};
    BumpAllocator b;
    Allocator     a4 = allocator_bump(&b, x);
    do_some_allocs(a4);
    LOG("i=%d", (int)b.i);
    free(x.buf);
  }

  return 0;
}

static int pw_prompt(Bytes* b) {
  char* pw = sodium_malloc(MAX_PW_LEN);
  b->buf   = (u8*)pw;
  fprintf(stderr, "pw > ");
  ssize_t pw_len = getpass(pw, MAX_PW_LEN);
  if (pw_len > 0)
    b->len = pw_len;
  if (pw_len < 0)
    return 1;
  return 0;
}

static int demo_keyread(int argc, char** argv) {
  CHECK(argc == 2, "must pass a path");
  const char* path = argv[1];

  u8    contents_buf[256];
  Bytes contents = BytesArray(contents_buf);

  uv_file fd;
  CHECK0(uvco_fs_open(loop, path, UV_FS_O_RDONLY, 0, &fd));
  CHECK0(uvco_fs_read(loop, fd, &contents, 0));
  uvco_fs_close(loop, fd);
  LOG("read %d", (int)contents.len);
  CHECK(contents.len < 256);

  CryptoSignSK sk;
  Bytes        pw = {0};
  CHECK0(keyio_keydecode(contents, pw, &sk));
  LOGB(CryptoBytes(sk));

  return 0;
}

static int demo_keygen(int argc, char** argv) {
  // al is our general-purpose allocator
  Allocator       al           = allocatormi_allocator();
  CryptoAllocator cryptal_base = {al};
  // sal is our secrets allocator
  Allocator sal = allocator_crypto(&cryptal_base);

  // Generate a key
  CryptoSignKeypair* keys;
  CHECK0(Alloc_create(sal, &keys));
  CHECK0(crypto_sign_ed25519_keypair((u8*)&keys->pk, (u8*)&keys->sk));
  LOGB(CryptoBytes(keys->sk));

  // Get a passphrase
  u8    pw_buf[2048];
  Bytes pw = BytesArray(pw_buf);
  CHECK0(keyio_getpass(&pw));
  LOGS(pw);

  // Copy it for use in decode (keyencode will zero it out)
  u8 pw_buf2[2048];
  memcpy(pw_buf2, pw_buf, sizeof(pw_buf));
  Bytes pw2 = BytesArray(pw_buf2);
  pw2.len   = pw.len;

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

static int demo_pwhash(int argc, char** argv) {
  Bytes pw;
  CHECK0(pw_prompt(&pw));
  CHECK(pw.len > 0);

  // Hash the password
  u8  pw_hash[crypto_pwhash_STRBYTES];
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

static int demo_tcp2(int argc, char** argv) {
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

static int demo_time(int argc, char** argv) {
  {
    struct taia t;
    taia_now(&t);
    char buf[TAIN_PACK];
    tain_pack(buf, &t);
    LOGB(BytesArray(buf));
  }
  {
    uv_timespec64_t sp;
    uv_clock_gettime(UV_CLOCK_MONOTONIC, &sp);
    LOG("secs=%" PRIi64 " nsec=%d", sp.tv_sec, sp.tv_nsec);
  }
  return 0;
}

static int demo_opts(int argc, char** argv) {
  struct optparse options;
  optparse_init(&options, argv);
  int                  option;
  struct optparse_long longopts[] =       //
      {{"help", 'h', OPTPARSE_NONE},      //
       {"port", 'p', OPTPARSE_REQUIRED},  //
       {0}};

  int port = 0;

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'h':
        cli_usage("opts", 0, longopts);
        return 1;
      case 'p':
        port = atoi(options.optarg);
        break;
      case '?':
        cli_usage("opts", 0, longopts);
        return 1;
    }
  }

  LOG("port=%d", port);
  return 0;
}

typedef struct {
  int       argc;
  char**    argv;
  Allocator allocator;
} MainCoroCtx;

static const CliCmd commands[] = {
    {"demo-opts", demo_opts},             //
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
    {"demo-tcp2", demo_tcp2},             //
    {"demo-time", demo_time},             //
    {"demo-echo", demo_echo},             //
    {"pk", pk_main},                      //
    {0},
};

static void coro_exit(int code) { mco_push(mco_running(), &code, 1); }

static void main_coro(mco_coro* co) {
  MainCoroCtx* ctx = (MainCoroCtx*)mco_get_user_data(co);

  int    argc = ctx->argc;
  char** argv = ctx->argv;

  for (usize i = 0; i < (ARRAY_LEN(commands) - 1) && argc > 1; ++i) {
    if (!strcmp(commands[i].cmd, argv[1]))
      return coro_exit(commands[i].fn(argc - 1, argv + 1));
  }

  fprintf(stderr, "unrecognized cmd\n");
  cli_usage("cli", commands, 0);
  return coro_exit(1);
}

#define MAIN_STACK_SIZE 1 << 22  // 4MiB
#define STACK_ALIGN     4096

static void* mco_alloc(size_t size, void* udata) {
  MainCoroCtx* ctx = udata;
  Bytes        stack;
  CHECK0(allocator_alloc(ctx->allocator, &stack, MAIN_STACK_SIZE, STACK_ALIGN));
  return stack.buf;
}

static void mco_dealloc(void* ptr, size_t size, void* udata) {
  MainCoroCtx* ctx = udata;
  allocator_free(ctx->allocator, Bytes(ptr, size));
}

int main(int argc, char** argv) {
  LOG("");

  // Allocator
  Allocator al = allocatormi_allocator();

  // libsodium init
  CHECK0(sodium_init());

  // libuv init
  CHECK0(Alloc_create(al, &loop));
  uv_loop_init(loop);

  // coro init
  MainCoroCtx ctx     = {argc, argv, al};
  mco_desc    desc    = mco_desc_init(main_coro, MAIN_STACK_SIZE);
  desc.allocator_data = &ctx;
  desc.alloc_cb       = mco_alloc;
  desc.dealloc_cb     = mco_dealloc;
  desc.user_data      = &ctx;
  mco_coro* co;
  CHECK(mco_create(&co, &desc) == MCO_SUCCESS);

  // run
  CHECK(mco_resume(co) == MCO_SUCCESS);
  if (mco_status(co) == MCO_SUSPENDED) {
    uv_run(loop, UV_RUN_DEFAULT);
    LOG("uv loop exit");
  }

  int rc = 0;
  if (mco_get_storage_size(co) > 0)
    mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  uv_loop_close(loop);
  Alloc_destroy(al, loop);

  if (rc == 0)
    LOG("ok");
  else
    LOG("ERROR code=%d", rc);
  return rc;
}
