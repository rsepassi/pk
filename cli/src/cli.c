#include "cli.h"

// vendor deps
#include "libbase58.h"
#include "lmdb.h"
#include "mimalloc.h"
#include "minicoro.h"
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
#include "xshmem.h"

#define MAX_PW_LEN 2048

// Defined in pk.c
int pk_main(int argc, char** argv);
// Defined in echo.c
int demo_echo(int argc, char** argv);
// Defined in disco.c
int demo_disco(int argc, char** argv);
// Defined in tcp2.c
int demo_tcp2(int argc, char** argv);

// Global event loop
uv_loop_t* loop;

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

  Bytes key = Str0(argv[2]);
  Bytes val = cmd == KvPut ? Str0(argv[3]) : BytesZero;

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
    uv_buf_t buf     = UvBuf(peer_id);
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
  LOGS(Str0((char*)pw_hash));
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

static int thread_runfn(void* arg) {
  int* x = arg;
  *x     = *x + 1;
  return 0;
}

static int demo_thread(int argc, char** argv) {
  LOG("");
  int x = 22;
  CHECK0(uvco_trun(loop, thread_runfn, &x));
  CHECK(x == 23);
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

static int demo_shm(int argc, char** argv) {
  int create = 0;
  Str f = BytesZero;

  struct optparse opts;
  optparse_init(&opts, argv);
  int option;
  while ((option = optparse(&opts, "cf:")) != -1) {
    switch (option) {
    case 'c':
      create = 1;
      break;
    case 'f':
      f = Str0(opts.optarg);
      break;
    case '?':
      LOGE("unrecognized option %c", option);
      return 1;
  }
  }

  CHECK(f.len);
  LOGS(f);

  XShmem shmem;
  if (create) {
    CHECK0(xshmem_create(&shmem, f, 4096));
    char* s = "77 hello world!";
    memcpy(shmem.mem.buf, s, strlen(s) + 1);
    LOG("sleep...");
    uvco_sleep(loop, 10000);
  } else {
    CHECK0(xshmem_open(&shmem, f, 4096));
    LOGS(Str0(shmem.mem.buf));
  }

  xshmem_close(&shmem);
  return 0;
}

typedef struct {
  int       argc;
  char**    argv;
  Allocator allocator;
  int       status;
} MainCoroCtx;

static const CliCmd commands[] = {
    {"demo-opts", demo_opts},             //
    {"demo-keygen", demo_keygen},         //
    {"demo-keyread", demo_keyread},       //
    {"demo-kv", demo_kv},                 //
    {"demo-mimalloc", demo_mimalloc},     //
    {"demo-multicast", demo_multicast},   //
    {"demo-pwhash", demo_pwhash},         //
    {"demo-sshkeyread", demosshkeyread},  //
    {"demo-vterm", demo_vterm},           //
    {"demo-tcp2", demo_tcp2},             //
    {"demo-time", demo_time},             //
    {"demo-echo", demo_echo},             //
    {"demo-thread", demo_thread},         //
    {"demo-disco", demo_disco},           //
    {"demo-shm", demo_shm},           //
    {"pk", pk_main},                      //
    {0},
};

static int main_coro(int argc, char** argv, CocoMainArg arg) {
  loop = arg.loop;

  // libsodium init
  CHECK0(sodium_init());

  for (usize i = 0; i < (ARRAY_LEN(commands) - 1) && argc > 1; ++i) {
    if (!strcmp(commands[i].cmd, argv[1])) {
      return commands[i].fn(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "unrecognized cmd\n");
  cli_usage("cli", commands, 0);
  return 1;
}

int main(int argc, char** argv) {
  CocoMainOpts opts = {0};
  opts.stack_size   = 1 << 22;  // 4 MiB
  opts.fn           = main_coro;
  return uvco_main(argc, argv, opts);
}
