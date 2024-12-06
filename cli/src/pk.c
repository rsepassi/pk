#include "bip39.h"
#include "cli.h"
#include "crypto.h"
#include "libbase58.h"
#include "lmdb.h"
#include "log.h"
#include "qrcodegen.h"
#include "uv.h"

#define PEER2_URL           "https://peer2.xyz"
#define PEER2_URLKEY_PREFIX (PEER2_URL "?key=")

// =============================================================================
// DATA
// =============================================================================
#define PkUserName_PREFIX "user."
typedef struct __attribute__((packed)) {
  u8 prefix[STRLEN(PkUserName_PREFIX)];
  u8 len;
  u8 name[34];
} PkUserName;

#define PkUserKeys_KEY "keys"
typedef struct __attribute__((packed)) {
  CryptoKxPK pk;
  CryptoSig  sig;
} PkUserShorttermPub;
typedef struct __attribute__((packed)) {
  CryptoKxSK         sk;
  PkUserShorttermPub pk;
} PkUserShortterm;
typedef struct __attribute__((packed)) {
  CryptoSignSK    sign;
  PkUserShortterm shortterm;
} PkUserKeys;

static int PkUserName_init(PkUserName* username, char* name) {
  *username = (PkUserName){0};
  memcpy(username->prefix, PkUserName_PREFIX, sizeof(username->prefix));
  if (strlen(name) > sizeof(username->name))
    return 1;
  username->len = (u8)strlen(name);
  memcpy(username->name, name, username->len);
  return 0;
}

static int PkUserKeys_init(PkUserKeys* keys) {
  *keys = (PkUserKeys){0};

  CryptoSignPK pk;
  if (crypto_sign_ed25519_keypair((u8*)&pk, (u8*)&keys->sign))
    return 1;

  if (crypto_kx_keypair((u8*)&keys->shortterm.pk.pk, (u8*)&keys->shortterm.sk))
    return 1;

  if (crypto_sign_ed25519_detached(
          (u8*)&keys->shortterm.pk.sig, 0, (u8*)&keys->shortterm.pk.pk,
          sizeof(keys->shortterm.pk.pk), (u8*)&keys->sign))
    return 1;

  return 0;
}
// =============================================================================
// DATA end
// =============================================================================

typedef struct {
  Str      datadir;
  MDB_env* kv;
  MDB_dbi  db;
} Pk;
Pk* pk_ctx = 0;

static void pk_user_new_usage() { fprintf(stderr, "user new <name>\n"); }
static void pk_user_del_usage() { fprintf(stderr, "user del <name>\n"); }

static int pk_user_exists(char* name, bool* exists) {
  *exists = false;

  MDB_txn* txn;
  MDB_dbi  userdb;
  if (mdb_txn_begin(pk_ctx->kv, 0, MDB_RDONLY, &txn))
    return 1;
  int rc = mdb_dbi_open(txn, name, 0, &userdb);
  if (rc == 0) {
    *exists = true;
    mdb_dbi_close(pk_ctx->kv, userdb);
  } else if (rc == MDB_NOTFOUND) {
    rc = 0;
  } else {
  }

  mdb_txn_abort(txn);
  return rc;
}

static int pk_user_new(int argc, char** argv) {
  LOG("");
  if (argc < 2) {
    fprintf(stderr, "must provide name\n");
    pk_user_new_usage();
    return 1;
  }
  char* name = argv[1];

  PkUserName username;
  if (PkUserName_init(&username, name))
    return 1;

  MDB_dbi  userdb;
  MDB_txn* txn;

  bool exists;
  if (pk_user_exists(name, &exists))
    return 1;
  if (exists) {
    LOG("user %s already exists", name);
    return 1;
  }

  {
    if (mdb_txn_begin(pk_ctx->kv, 0, 0, &txn))
      goto err0;
    // Insert the user's keys into their db
    {
      if (mdb_dbi_open(txn, name, MDB_CREATE, &userdb))
        goto err1;
      Str        key = Str(PkUserKeys_KEY);
      PkUserKeys user_keys;
      if (PkUserKeys_init(&user_keys))
        goto err2;
      Bytes val = BytesObj(user_keys);
      if (mdb_put(txn, userdb, (void*)&key, (void*)&val, 0))
        goto err2;
    }

    // Add the user to the meta db
    {
      Bytes   key         = BytesObj(username);
      u8      val_data[1] = {1};
      MDB_val val         = {1, val_data};
      if (mdb_put(txn, pk_ctx->db, (void*)&key, &val, 0))
        goto err2;
    }
    if (mdb_txn_commit(txn))
      goto err2;
  }

  return 0;

err2:
  mdb_dbi_close(pk_ctx->kv, userdb);
err1:
  mdb_txn_abort(txn);
err0:
  return 1;
}

static int pk_user_show(int argc, char** argv) {
  LOG("");
  int rc = 1;

  if (argc < 2) {
    fprintf(stderr, "must provide name\n");
    pk_user_del_usage();
    return 1;
  }

  char*      name = argv[1];
  PkUserName username;
  if (PkUserName_init(&username, name))
    return 1;

  MDB_txn* txn;
  if (mdb_txn_begin(pk_ctx->kv, 0, MDB_RDONLY, &txn))
    return 1;

  MDB_dbi userdb;
  if (mdb_dbi_open(txn, name, 0, &userdb))
    goto err1;
  Str key = Str(PkUserKeys_KEY);
  Str val;
  if (mdb_get(txn, userdb, (void*)&key, (void*)&val))
    goto err2;

  // hex public key
  PkUserKeys user_keys;
  bytes_copy(&BytesObj(user_keys), val);
  CryptoSignPK* pk       = &user_keys.sign.pk;
  Bytes         pk_bytes = BytesObj(*pk);
  fprinthex(stdout, "pk", pk_bytes.buf, pk_bytes.len);
  fprintf(stdout, "\n");

  // b58check public key
  char  b58_buf[sizeof(*pk) * 2];
  usize b58_len = sizeof(b58_buf);
  if (!b58check_enc(b58_buf, &b58_len, 1, pk, sizeof(*pk)))
    return 1;
  fprintf(stdout, "pk-b58(%d)=%.*s\n", (int)(b58_len - 1), (int)(b58_len - 1),
          b58_buf);

  // bip39 word list
  fprintf(stdout, "pk-bip39:\n");
  u16 word_idxs[bip39_MNEMONIC_LEN(sizeof(*pk))];
  CHECK0(bip39_mnemonic_idxs(BytesObj(*pk), word_idxs));
  usize linei = 0;
  for (usize i = 0; i < ARRAY_LEN(word_idxs); ++i) {
    if (i && i % 6 == 0) {
      fprintf(stdout, "\n");
      linei = 0;
    }
    fprintf(stdout, "%s%2d. %-8s", linei ? " " : "", (int)(i + 1),
            bip39_words[word_idxs[i]]);
    ++linei;
  }
  fprintf(stdout, "\n");

  // QR
  uint8_t url[STRLEN(PEER2_URLKEY_PREFIX) + sizeof(b58_buf)] =
      PEER2_URLKEY_PREFIX;
  memcpy(url + STRLEN(PEER2_URLKEY_PREFIX), b58_buf, b58_len - 1);
  uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
  CHECK(qrcodegen_ez_encode(url, STRLEN(PEER2_URLKEY_PREFIX) + b58_len - 1,
                            qrcode));
  qrcodegen_console_print(stdout, qrcode);

  return 0;

err2:
  mdb_dbi_close(pk_ctx->kv, userdb);
err1:
  mdb_txn_abort(txn);
  return rc;
}

static int pk_user_del(int argc, char** argv) {
  LOG("");

  int rc = 1;

  if (argc < 2) {
    fprintf(stderr, "must provide name\n");
    pk_user_del_usage();
    return 1;
  }

  char*      name = argv[1];
  PkUserName username;
  if (PkUserName_init(&username, name))
    return 1;

  MDB_txn* txn;
  if (mdb_txn_begin(pk_ctx->kv, 0, 0, &txn))
    return 1;

  MDB_dbi userdb;
  if (mdb_dbi_open(txn, name, 0, &userdb))
    goto err1;
  if (mdb_drop(txn, userdb, 1))
    goto err2;

  MDB_val key = {sizeof(PkUserName), &username};
  if (mdb_del(txn, pk_ctx->db, &key, 0))
    goto err1;

  mdb_txn_commit(txn);
  return 0;

err2:
  mdb_dbi_close(pk_ctx->kv, userdb);
err1:
  mdb_txn_abort(txn);
  return rc;
}

static int pk_user_ls(int argc, char** argv) {
  int rc = 1;

  MDB_txn* txn;
  if (mdb_txn_begin(pk_ctx->kv, 0, MDB_RDONLY, &txn))
    return 1;

  MDB_cursor* cur;
  if (mdb_cursor_open(txn, pk_ctx->db, &cur))
    goto out1;

  Str key = Str(PkUserName_PREFIX);
  if (mdb_cursor_get(cur, (void*)&key, 0, MDB_SET_RANGE))
    goto ok;

  while (1) {
    if (mdb_cursor_get(cur, (void*)&key, 0, MDB_GET_CURRENT))
      break;
    if (!str_startswith(key, Str(PkUserName_PREFIX)))
      break;
    PkUserName username;
    bytes_copy(&BytesObj(username), key);
    fprintf(stdout, "%.*s\n", (int)username.len, username.name);
    if (mdb_cursor_get(cur, 0, 0, MDB_NEXT))
      break;
  }

ok:
  rc = 0;
  mdb_cursor_close(cur);
out1:
  mdb_txn_abort(txn);
  return rc;
}

static const CliCmd pk_user_commands[] = {
    {"new", pk_user_new},    //
    {"del", pk_user_del},    //
    {"ls", pk_user_ls},      //
    {"show", pk_user_show},  //
    {0},
};

static int pk_user(int argc, char** argv) {
  LOG("");
  if (argc < 2) {
    fprintf(stderr, "missing subcommand\n");
    cli_usage("user", pk_user_commands, 0);
    return 1;
  }
  return cli_dispatch("user", pk_user_commands, argc - 1, argv + 1);
}

static const CliCmd pk_commands[] = {
    {"user", pk_user},  //
    {0},
};

static int pk_datadir_setup(Pk* ctx) {
  char  kv_path_buf[1024];
  char* kv_path = kv_path_buf;
  if (ctx->datadir.len > 1000)
    goto err0;

  const char* fname = "/data.kv";
  memcpy(kv_path, ctx->datadir.buf, ctx->datadir.len);
  kv_path += ctx->datadir.len;
  memcpy(kv_path, fname, strlen(fname));
  kv_path += strlen(fname);
  kv_path[0] = 0;

  kv_path = kv_path_buf;

  mode_t kv_mode = S_IRUSR | S_IWUSR | S_IRGRP;  // rw-r-----
  if (mdb_env_create(&ctx->kv))
    goto err0;
  if (mdb_env_set_maxdbs(ctx->kv, 8))
    goto err0;
  if (mdb_env_open(ctx->kv, kv_path, MDB_NOSUBDIR | MDB_NOLOCK, kv_mode))
    goto err1;

  MDB_txn* txn;
  if (mdb_txn_begin(ctx->kv, 0, 0, &txn))
    goto err1;
  if (mdb_dbi_open(txn, 0, 0, &ctx->db))
    goto err2;
  if (mdb_txn_commit(txn))
    goto err3;

  return 0;

err3:
  mdb_dbi_close(ctx->kv, ctx->db);
err2:
  mdb_txn_abort(txn);
err1:
  mdb_env_close(ctx->kv);
err0:
  return 1;
}

int pk_main(int argc, char** argv) {
  LOG("");

  STATIC_CHECK(sizeof(Bytes) == sizeof(MDB_val));

  struct optparse options;
  optparse_init(&options, argv);
  options.permute = 0;
  int option;

  struct optparse_long longopts[] =       //
      {{"help", 'h', OPTPARSE_NONE},      //
       {"data", 'd', OPTPARSE_REQUIRED},  //
       {0}};

  Str datadir = Str("/tmp/pk-data");

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'h':
        cli_usage("pk", pk_commands, longopts);
        return 1;
      case 'd':
        datadir = Str0(options.optarg);
        break;
      case '?':
        cli_usage("pk", pk_commands, longopts);
        return 1;
    }
  }

  argc -= options.optind;
  argv += options.optind;

  if (!argv[0]) {
    fprintf(stderr, "missing subcommand\n");
    cli_usage("pk", pk_commands, longopts);
    return 1;
  }

  LOGS(datadir);
  Pk ctx      = {0};
  ctx.datadir = datadir;
  pk_ctx      = &ctx;
  CHECK0(pk_datadir_setup(&ctx));
  return cli_dispatch("pk", pk_commands, argc, argv);
}
