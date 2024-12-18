#include "crypto.h"

#include "log.h"

static AllocStatus alloc_crypto(void* ctx, Bytes* buf, usize sz, usize align) {
  CryptoAllocator* al = ctx;

  if (sz == 0)
    sodium_munlock(buf->buf, buf->len);

  AllocStatus rc = allocator_realloc(al->base, buf, sz, align);
  if (rc)
    return rc;

  if (sz)
    if (sodium_mlock(buf->buf, buf->len))
      return 1;
  return 0;
}

Allocator allocator_crypto(CryptoAllocator* base) {
  return (Allocator){base, alloc_crypto, 0};
}

static int parsehex(Bytes out, Bytes hex) {
  if (hex.len != out.len * 2)
    return 1;
  usize binlen;
  if (sodium_hex2bin(out.buf, out.len, (char*)hex.buf, hex.len, 0, &binlen,
                     0))
    return 1;
  CHECK(binlen == out.len);
  return 0;
}

int CryptoSignPK_parsehex(CryptoSignPK* pk, Bytes hex) {
  return parsehex(BytesObj(*pk), hex);
}

int CryptoSignSK_parsehex(CryptoSignSK* sk, Bytes hex) {
  return parsehex(BytesObj(*sk), hex);
}
