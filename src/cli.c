// src

// vendor deps
#include "argparse.h"
#include "libbase58.h"
#include "lmdb.h"
#include "mimalloc.h"
#include "minicoro.h"
#include "plum/plum.h"
#include "uv.h"
#include "vterm.h"

// lib
#include "allocatormi.h"
#include "base64.h"
#include "crypto.h"
#include "getpass.h"
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

void CxnCb(NIK_Cxn *cxn, void *userdata, NIK_Cxn_Event e, Bytes data, u64 now) {
  LOGS(data);
}

int demo_nikcxn(int argc, const char **argv) {
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

  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk};

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
    Bytes msg1 = str_from_c("hi from A");
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
    NIK_HandshakeMsg1 *msg1 = (NIK_HandshakeMsg1 *)hs1.buf;
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
    NIK_Cxn *initiator = delay == delay_A ? &cxn_A : &cxn_B;
    NIK_Cxn *responder = delay == delay_A ? &cxn_B : &cxn_A;
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
    nik_cxn_enqueue(initiator, str_from_c("complete"));
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

  u32 id_i = 1;
  u32 id_r = 2;
  NIK_Keys hkeys_A = {&kx_keys_i.pk, &kx_keys_i.sk, &kx_keys_r.pk};
  NIK_Keys hkeys_B = {&kx_keys_r.pk, &kx_keys_r.sk, &kx_keys_i.pk};

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
  phex("tx.send", (u8 *)&tx_i.send, sizeof(tx_i.send));
  phex("tx.recv", (u8 *)&tx_i.recv, sizeof(tx_i.recv));
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
  CHECK(tx_r.counter_max == 2);

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
    char *salt_str = "__salthash";
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

int demo_base64(int argc, const char **argv) {
  Str a = str_from_c("hello world!");

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

void vt_cb(const char *s, size_t len, void *user) {
  LOG("vt(%d)=%.*s", (int)len, (int)len, s);
}

int demo_vterm(int argc, const char **argv) {
  int rows = 100;
  int cols = 80;
  VTerm *vt = vterm_new(rows, cols);
  vterm_set_utf8(vt, true);

  VTermScreen *vt_screen = vterm_obtain_screen(vt);
  vterm_screen_reset(vt_screen, true);

  // VTermState *vt_state = vterm_obtain_state(vt);
  // vterm_state_reset(vt_state, 1);

  Str txt = str_from_c("hi!");
  vterm_input_write(vt, (char *)txt.buf, txt.len);

  vterm_output_set_callback(vt, vt_cb, NULL);
  vterm_keyboard_unichar(vt, 65, 0);
  vterm_keyboard_key(vt, VTERM_KEY_ENTER, 0);

  vterm_free(vt);
  return 0;
}

void get_identity_key(Str hex, CryptoSignSK *out) {
  CHECK(hex.len == 64, "got length %d", (int)hex.len);
  CryptoSeed seed;
  sodium_hex2bin((u8 *)&seed, sizeof(CryptoSeed), (char *)hex.buf, hex.len, 0,
                 0, 0);

  CryptoSignPK pk;
  CHECK0(crypto_sign_seed_keypair((u8 *)&pk, (u8 *)out, (u8 *)&seed));
}

int drat_a_to_b(DratState *A_state, X3DH *A_x, DratState *B_state, X3DH *B_x,
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

int demo_drat(int argc, const char **argv) {
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
    CHECK0(memcmp((u8 *)&A_x, (u8 *)&B_x, sizeof(X3DH)));
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
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x, //
                     str_from_c("hello from Bob! secret number is 77")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x, //
                     str_from_c("hello from Bob! secret number is 79")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x, //
                     str_from_c("hello from Alice!")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x, //
                     str_from_c("roger roger")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x, //
                     str_from_c("roger roger 2")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x, //
                     str_from_c("1")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x, //
                     str_from_c("2")));

  return 0;
}

int demo_x3dh(int argc, const char **argv) {
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
  CHECK0(memcmp((u8 *)&A_x, (u8 *)&B_x, sizeof(X3DH)));
  LOG("keys match!");

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

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  *buf = uv_buf_init(malloc(suggested_size), suggested_size);
}

void recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
             const struct sockaddr *addr, unsigned flags) {
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
                      const plum_mapping_t *mapping) {
  LOG("map!");
  CHECK(state == PLUM_STATE_SUCCESS);
  LOG("External address: %s:%hu\n", mapping->external_host,
      mapping->external_port);
}

int demo_multicast(int argc, const char **argv) {
  bool send = argc > 1 && memcmp(argv[1], "send", 4) == 0;

  LOG("udp init");
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  char *multicast_group = "239.0.0.22";
  int port = 20000;

  if (send) {
    struct sockaddr_in myaddr;
    CHECK0(uv_ip4_addr("0.0.0.0", 0, &myaddr));
    CHECK0(uv_udp_bind(&udp, (struct sockaddr *)&myaddr, 0));

    struct sockaddr_storage localbind;
    int len;
    CHECK0(uv_udp_getsockname(&udp, (struct sockaddr *)&localbind, &len));
    LOG("addrlen=%d", len);
    // LOG("addr=%u", ((struct sockaddr_in*)&localbind)->sin_addr.s_addr);

    LOG("udp send");
    struct sockaddr_in multi_addr;
    CHECK0(uv_ip4_addr(multicast_group, port, &multi_addr));
    Str peer_id = str_from_c("mike multicast");
    uv_buf_t buf = uv_buf_init((char *)peer_id.buf, peer_id.len);
    CHECK0(uvco_udp_send(loop, &udp, &buf, 1, (struct sockaddr *)&multi_addr));
    LOG("sent!");
    uvco_sleep(loop, 1000);
  } else {
    struct sockaddr_in myaddr;
    CHECK0(uv_ip4_addr("0.0.0.0", port, &myaddr));

    CHECK0(uv_udp_bind(&udp, (struct sockaddr *)&myaddr, 0));
    CHECK0(uv_udp_set_membership(&udp, multicast_group, NULL, UV_JOIN_GROUP));

    LOG("udp recv multicast on %s %d", multicast_group, port);
    CHECK0(uv_udp_recv_start(&udp, alloc_cb, recv_cb));

    uvco_sleep(loop, 60000);
    uv_udp_recv_stop(&udp);
  }
  return 0;
}

int demo_holepunch(int argc, const char **argv) {

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
  Str peer_id = str_from_c("mike multicast");
  uv_buf_t buf = uv_buf_init((char *)peer_id.buf, peer_id.len);
  CHECK0(uvco_udp_send(loop, &udp, &buf, 1, (struct sockaddr *)&peer_addr));
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

  allocator_free(a, &b1);
  allocator_free(a, &b2);

  allocator_deinit(a);
}

int demo_mimalloc(int argc, const char **argv) {
  // MIMALLOC_SHOW_STATS=1
  mi_option_enable(mi_option_show_stats);

  Allocator a1 = allocatormi_allocator();
  do_some_allocs(a1);

  Allocator a2 = allocatormi_heap();
  do_some_allocs(a2);

  Bytes x = allocatormi_block_alloc(1);
  Allocator a3 = allocatormi_arena(x, true);
  do_some_allocs(a3);
  allocatormi_block_free(x);

  return 0;
}

static const char *const usages[] = {
    "pk [options] [cmd] [args]\n\n    Commands:"
    "\n      - demo-vterm"
    "\n      - demo-base64"
    "\n      - demo-x3dh"
    "\n      - demo-drat"
    "\n      - demo-kv"
    "\n      - demo-nik"
    "\n      - demo-nikcxn"
    "\n      - demo-b58"
    "\n      - demo-mimalloc"
    "\n      - demo-multicast"
    "\n      - demo-holepunch" //
    ,
    NULL,
};

struct cmd_struct {
  const char *cmd;
  int (*fn)(int, const char **);
};

static struct cmd_struct commands[] = {
    {"demo-vterm", demo_vterm},         //
    {"demo-x3dh", demo_x3dh},           //
    {"demo-drat", demo_drat},           //
    {"demo-base64", demo_base64},       //
    {"demo-kv", demo_kv},               //
    {"demo-nik", demo_nik},             //
    {"demo-nikcxn", demo_nikcxn},       //
    {"demo-b58", demo_b58},             //
    {"demo-mimalloc", demo_mimalloc},   //
    {"demo-holepunch", demo_holepunch}, //
    {"demo-multicast", demo_multicast}, //
};

typedef struct {
  int argc;
  const char **argv;
} MainCoroCtx;

void coro_exit(int code) { mco_push(mco_running(), &code, 1); }

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
  LOG("uv loop done");

  int rc = 0;
  if (mco_get_storage_size(co) > 0)
    mco_pop(co, &rc, 1);

  // coro deinit
  CHECK(mco_status(co) == MCO_DEAD);
  CHECK(mco_destroy(co) == MCO_SUCCESS);

  // libuv deinit
  // uv_loop_close(loop);  SEGFAULTS! TODO
  free(loop);

  if (rc == 0)
    LOG("goodbye");
  else
    LOG("ERROR code=%d", rc);
  return rc;
}
