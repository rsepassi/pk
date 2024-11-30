#include "keyio.h"

#include "base64.h"
#include "getpass.h"
#include "log.h"
#include "stdmacros.h"

#include <stdio.h>

#ifdef BYTE_ORDER_LE
#define ntohl SWAP_U32
#else
#define ntohl(x) (x)
#endif

#define PK_PK_HEADER "Ed25519 "
#define PK_PK_FOOTER "\n"
#define PK_SK_HEADER "-----BEGIN PK PRIVATE KEY-----\n"
#define PK_SK_FOOTER "\n-----END PK PRIVATE KEY-----\n"
#define PK_SKP_HEADER "-----BEGIN PROTECTED PK PRIVATE KEY-----\n"
#define PK_SKP_FOOTER "\n-----END PROTECTED PK PRIVATE KEY-----\n"
#define OPENSSH_SK_HEADER "-----BEGIN OPENSSH PRIVATE KEY-----"
#define OPENSSH_SK_FOOTER "-----END OPENSSH PRIVATE KEY-----"

int keyio_getpass(Bytes* pw) {
  fprintf(stderr, "passphrase > ");
  ssize_t pw_len = getpass((char*)pw->buf, pw->len);
  if (pw_len < 0)
    return (int)pw_len;
  pw->len = pw_len;
  return 0;
}

static int encode(Bytes bin, Allocator al, Str header, Str footer, Str* out) {
  // Allocate the output
  usize b64_len =
      sodium_base64_encoded_len(bin.len, sodium_base64_VARIANT_ORIGINAL);
  // -1 because sodium '0'-terminates the base64 but we remove it
  usize outlen = b64_len + header.len + footer.len - 1;
  if (allocator_u8(al, out, outlen))
    return 1;

  // Header
  u8* outp = out->buf;
  memcpy(outp, header.buf, header.len);
  outp += header.len;

  // base64-encoded binary data
  sodium_bin2base64((char*)outp, b64_len, bin.buf, bin.len,
                    sodium_base64_VARIANT_ORIGINAL);
  --outp;  // '0' added by sodium
  outp += b64_len;

  // Footer
  memcpy(outp, footer.buf, footer.len);
  outp += footer.len;

  CHECK((usize)(outp - out->buf) == outlen);
  return 0;
}

static int sk_pw_encode(const CryptoSignSK* sk, Str password, Allocator al,
                        Str* sk_out) {
  int rc = 1;

  // Derive a key
  u8 key[crypto_secretbox_KEYBYTES];
  u8 salt[crypto_pwhash_SALTBYTES];
  {
    randombytes_buf(salt, sizeof(salt));
    u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    if (crypto_pwhash(key, sizeof(key), (char*)password.buf, password.len, salt,
                      opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13))
      return 1;
    sodium_memzero(password.buf, password.len);
  }

  // Encrypt the private key with the derived key and a random nonce
  u8 sk_enc[crypto_sign_ed25519_SEEDBYTES + crypto_secretbox_MACBYTES];
  u8 nonce[crypto_secretbox_NONCEBYTES];
  {
    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_secretbox_easy(sk_enc, (u8*)&sk->seed,
                              crypto_sign_ed25519_SEEDBYTES, nonce, key))
      return 1;

    // To aid in debugging roundtrips:
    // LOGB(bytes_from_arr(nonce));
    // LOGB(bytes_from_arr(salt));
    // LOGB(bytes_from_arr(key));

    sodium_memzero(key, sizeof(key));
  }

  // Prepare our binary output = salt + nonce + cryptsk + pk
  u8 src[sizeof(salt) + sizeof(nonce) + sizeof(sk_enc) + sizeof(sk->pk)];
  {
    u8* srcp = src;
    memcpy(srcp, salt, sizeof(salt));
    srcp += sizeof(salt);
    memcpy(srcp, nonce, sizeof(nonce));
    srcp += sizeof(nonce);
    memcpy(srcp, sk_enc, sizeof(sk_enc));
    srcp += sizeof(sk_enc);
    memcpy(srcp, (u8*)&sk->pk, sizeof(sk->pk));
    srcp += sizeof(sk->pk);

    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(sk_enc, sizeof(sk_enc));
  }

  // Prepare our final textual output
  if (encode(bytes_from_arr(src), al, Str(PK_SKP_HEADER), Str(PK_SKP_FOOTER),
             sk_out))
    return 1;
  sodium_memzero(src, sizeof(src));

  // Success
  rc = 0;

  return rc;
}

static int sk_encode(const CryptoSignSK* sk, Allocator al, Str* sk_out) {
  if (encode(CryptoBytes(*sk), al, Str(PK_SK_HEADER), Str(PK_SK_FOOTER),
             sk_out))
    return 1;
  return 0;
}

static int pk_encode(const CryptoSignPK* pk, Allocator al, Str* pk_out) {
  if (encode(CryptoBytes(*pk), al, Str(PK_PK_HEADER), Str(PK_PK_FOOTER),
             pk_out))
    return 1;
  return 0;
}

int keyio_keyencode(const CryptoSignKeypair* keys, Str password, Allocator al,
                    Str* sk_out, Str* pk_out) {
  if (password.len > 0) {
    if (sk_pw_encode(&keys->sk, password, al, sk_out))
      return 1;
  } else {
    if (sk_encode(&keys->sk, al, sk_out))
      return 1;
  }

  if (pk_encode(&keys->pk, al, pk_out))
    return 1;

  return 0;
}

bool keyio_key_is_pwprotected(Str buf) {
  return (buf.len > sizeof(PK_SKP_HEADER) &&
          memcmp(buf.buf, PK_SKP_HEADER, STRLEN(PK_SKP_HEADER)) == 0);
}

int keyio_keydecode(Str buf, Str password, CryptoSignSK* out) {
  // Determine if the contents are password-protected
  bool protected;
  usize ctr_sz;
  usize hdr_sz;
  if (buf.len > sizeof(PK_SK_HEADER) &&
      memcmp(buf.buf, PK_SK_HEADER, STRLEN(PK_SK_HEADER)) == 0) {
    protected = false;
    ctr_sz = sizeof(PK_SK_HEADER) + sizeof(PK_SK_FOOTER) - 2;
    hdr_sz = STRLEN(PK_SK_HEADER);
  } else if (buf.len > sizeof(PK_SKP_HEADER) &&
             memcmp(buf.buf, PK_SKP_HEADER, STRLEN(PK_SKP_HEADER)) == 0) {
    protected = true;
    ctr_sz = sizeof(PK_SKP_HEADER) + sizeof(PK_SKP_FOOTER) - 2;
    hdr_sz = STRLEN(PK_SKP_HEADER);
  } else {
    // Unrecognized header
    return 1;
  }

  if (buf.len <= ctr_sz)
    // Missing data
    return 1;

  // The base64-encoded contents
  usize contents_len = buf.len - ctr_sz;
  Bytes contents = {contents_len, buf.buf + hdr_sz};

  if (!protected) {
    // If not password-protected, decode directly into the output
    usize len;
    if (sodium_base642bin((u8*)out, sizeof(*out), (char*)contents.buf,
                          contents.len, 0, &len, 0,
                          sodium_base64_VARIANT_ORIGINAL))
      return 1;
    sodium_memzero(contents.buf, contents.len);
    if (len != sizeof(*out))
      return 1;

    return 0;
  }

  // The key is password-protected
  if (password.len == 0)
    return 1;

  // Decode
  u8 dec[crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES +
         crypto_secretbox_MACBYTES + crypto_sign_ed25519_SECRETKEYBYTES];
  usize len;
  if (sodium_base642bin(dec, sizeof(dec), (char*)contents.buf, contents.len, 0,
                        &len, 0, sodium_base64_VARIANT_ORIGINAL))
    return 1;
  if (len != sizeof(dec))
    return 1;

  // Parse the parts
  u8* salt = dec;
  u8* nonce = salt + crypto_pwhash_SALTBYTES;
  u8* cipher = nonce + crypto_secretbox_NONCEBYTES;
  u8* pk = cipher + crypto_secretbox_MACBYTES + crypto_sign_ed25519_SEEDBYTES;

  // Populate the public key
  out->pk = *(CryptoSignPK*)pk;

  // Derive the key
  u8 key[crypto_secretbox_KEYBYTES];
  u64 opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  u64 memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  if (crypto_pwhash(key, sizeof(key), (char*)password.buf, password.len, salt,
                    opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13))
    return 1;
  sodium_memzero(password.buf, password.len);

  // To aid in debugging roundtrips:
  // LOGB(((Bytes){crypto_pwhash_SALTBYTES, salt}));
  // LOGB(((Bytes){crypto_secretbox_NONCEBYTES, nonce}));
  // LOGB(((Bytes){sizeof(key), key}));

  // Decrypt
  if (crypto_secretbox_open_easy((u8*)&out->seed, cipher,
                                 crypto_secretbox_MACBYTES +
                                     crypto_sign_ed25519_SEEDBYTES,
                                 nonce, key))
    return 1;

  return 0;
}

int keyio_keydecode_openssh(Str str, Allocator al, CryptoSignSK* out) {
  int rc = 1;

  // Resource allocation up front
  Bytes stripped;  // SECRET
  if (allocator_u8(al, &stripped, str.len))
    return 1;
  Bytes buf;  // SECRET
  usize sz = base64_decoded_maxlen(stripped.len);
  if (allocator_u8(al, &buf, sz)) {
    allocator_free(al, stripped);
    return 1;
  }
  u8 sk2[crypto_sign_ed25519_SECRETKEYBYTES];

  {
    stripped.len = 0;
    // Header line
    // memcmp OK: public line, and header starts with '-', a character that
    // does not appear in the base64 alphabet, which makes this constant time
    // with respect to the secret.
    usize i = 0;
    if (memcmp(&str.buf[i], OPENSSH_SK_HEADER, STRLEN(OPENSSH_SK_HEADER)))
      goto end;
    i += STRLEN(OPENSSH_SK_HEADER);
    ++i;  // \n

    // Copy the lines into stripped, excluding the newlines
    // memcmp OK: the footer starts with '-', a character that does not appear
    // in the base64 alphabet, which makes this constant time with respect
    // to the secret.
    while (memcmp(&str.buf[i], OPENSSH_SK_FOOTER, STRLEN(OPENSSH_SK_FOOTER)) !=
           0) {
      usize linestart = i;
      while (i < str.len && str.buf[i] != '\n')
        ++i;
      usize lineend = i;
      ++i;
      memcpy(&stripped.buf[stripped.len], &str.buf[linestart],
             lineend - linestart);
      stripped.len += lineend - linestart;
    }
    sodium_memzero(str.buf, str.len);
  }

  // base64 decode
  {
    usize len;
    if (sodium_base642bin(buf.buf, sz, (char*)stripped.buf, stripped.len, 0,
                          &len, 0, sodium_base64_VARIANT_ORIGINAL))
      goto end;
    buf.len = len;
  }

  // Parse
  //
  // From https://coolaj86.com/articles/the-openssh-private-key-format/
  // Also see: https://github.com/openssh/openssh-portable/blob/master/sshkey.c
  // And: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
  //
  // To look at the data in a key file:
  // cat id_ed25519 | head -n -1 | tail +2 | tr -d '\n' | base64 -d | hexdump -C
  //
  // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
  // 32-bit length, "none"   # ciphername length and string
  // 32-bit length, "none"   # kdfname length and string
  // 32-bit length, nil      # kdf (0 length, no kdf)
  // 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
  // 32-bit length, sshpub   # public key in ssh format
  //     32-bit length, keytype
  //     32-bit length, pub0
  //     32-bit length, pub1
  // 32-bit length for rnd+prv+comment+pad
  //     64-bit dummy checksum?  # a random 32-bit int, repeated
  //     32-bit length, keytype  # the private key (including public)
  //     32-bit length, pub0     # Public Key parts
  //     32-bit length, pub1
  //     32-bit length, prv0     # Private Key parts
  //     ...                     # (number varies by type)
  //     32-bit length, comment  # comment string
  //     padding bytes 0x010203  # pad to blocksize (see notes below)

  usize i = 0;
  u32 len = 0;

  // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
  while (i < buf.len && buf.buf[i] != 0)
    ++i;
  ++i;

  // 32-bit length, "none"   # ciphername length and string
  if ((i + 8) >= buf.len)
    goto end;
  i += 8;

  // 32-bit length, "none"   # kdfname length and string
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 8;

  // 32-bit length, nil      # kdf (0 length, no kdf)
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;
  if (len != 0)
    goto end;

  // 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
  len = ntohl(*(u32*)&buf.buf[i]);
  if (len != 1)
    goto end;
  i += 4;

  // 32-bit length, sshpub   # public key in ssh format
  i += 4;

  //     32-bit length, keytype
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, pub0
  len = ntohl(*(u32*)&buf.buf[i]);
  if (len != 32)
    goto end;
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  Bytes pk = {32, &buf.buf[i]};
  i += len;

  // 32-bit length for rnd+prv+comment+pad
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;

  //     64-bit dummy checksum?  # a random 32-bit int, repeated
  if ((i + 8) >= buf.len)
    goto end;
  i += 8;

  //     32-bit length, keytype  # the private key (including public)
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, pub0     # Public Key parts
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;
  if (len != 32)
    goto end;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, prv0     # Private Key parts
  len = ntohl(*(u32*)&buf.buf[i]);
  i += 4;
  if ((i + 32) >= buf.len)
    goto end;
  Bytes sk = {32, &buf.buf[i]};
  i += len;

  memcpy((u8*)&out->seed, sk.buf, sizeof(out->seed));
  memcpy((u8*)&out->pk, pk.buf, sizeof(out->pk));

  // Verify that the public key derivation matches libsodium's
  u8 pk2[crypto_sign_ed25519_PUBLICKEYBYTES];
  crypto_sign_ed25519_seed_keypair(pk2, sk2, sk.buf);
  if (sizeof(sk2) != sk.len * 2)
    goto end;
  if (sodium_memcmp(sk2, sk.buf, sizeof(sk2)))
    goto end;

  rc = 0;

end:
  sodium_memzero(sk2, sizeof(sk2));
  allocator_free(al, stripped);
  allocator_free(al, buf);
  return rc;
}
