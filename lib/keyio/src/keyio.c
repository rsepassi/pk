#include "keyio.h"

#include "base64.h"
#include "stdmacros.h"

#define OPENSSH_SK_HEADER "-----BEGIN OPENSSH PRIVATE KEY-----"
#define OPENSSH_SK_FOOTER "-----END OPENSSH PRIVATE KEY-----"

int keyio_openssh_parsekey(Str str, Allocator al, CryptoSignSK* out) {
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
  sodium_mlock(stripped.buf, stripped.len);
  sodium_mlock(buf.buf, buf.len);

  {
    stripped.len = 0;
    // Header line
    // memcmp OK: public line, and header starts with '-', a character that
    // does not appear in the base64 alphabet, which makes this constant time
    // with respect to the secret.
    usize i = 0;
    if (memcmp(&str.buf[i], OPENSSH_SK_HEADER, sizeof(OPENSSH_SK_HEADER) - 1))
      goto end;
    i += sizeof(OPENSSH_SK_HEADER) - 1;
    ++i;  // \n

    // Copy the lines into stripped, excluding the newlines
    // memcmp OK: the footer starts with '-', a character that does not appear
    // in the base64 alphabet, which makes this constant time with respect
    // to the secret.
    while (memcmp(&str.buf[i], OPENSSH_SK_FOOTER,
                  sizeof(OPENSSH_SK_FOOTER) - 1) != 0) {
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
  usize len = 0;

  // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
  while (i < buf.len && buf.buf[i] != 0)
    ++i;
  ++i;

  // 32-bit length, "none"   # ciphername length and string
  if ((i + 8) >= buf.len)
    goto end;
  i += 8;

  // 32-bit length, "none"   # kdfname length and string
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 8;

  // 32-bit length, nil      # kdf (0 length, no kdf)
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 4;
  if (len != 0)
    goto end;

  // 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  if (len != 1)
    goto end;
  i += 4;

  // 32-bit length, sshpub   # public key in ssh format
  i += 4;

  //     32-bit length, keytype
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, pub0
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  if (len != 32)
    goto end;
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  Bytes pk = {32, &buf.buf[i]};
  i += len;

  // 32-bit length for rnd+prv+comment+pad
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 4;

  //     64-bit dummy checksum?  # a random 32-bit int, repeated
  if ((i + 8) >= buf.len)
    goto end;
  i += 8;

  //     32-bit length, keytype  # the private key (including public)
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 4;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, pub0     # Public Key parts
  len = SWAP_U32(*(u32*)&buf.buf[i]);
  i += 4;
  if (len != 32)
    goto end;
  if ((i + len) >= buf.len)
    goto end;
  i += len;

  //     32-bit length, prv0     # Private Key parts
  len = SWAP_U32(*(u32*)&buf.buf[i]);
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
  sodium_memzero(stripped.buf, stripped.len);
  sodium_memzero(buf.buf, buf.len);
  sodium_munlock(stripped.buf, stripped.len);
  sodium_munlock(buf.buf, buf.len);
  allocator_free(al, stripped);
  allocator_free(al, buf);
  return rc;
}
