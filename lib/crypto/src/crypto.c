#include "crypto.h"

#include "log.h"

u8 crypto_init() {
  // sanity checks
  STATIC_CHECK(crypto_sign_ed25519_SECRETKEYBYTES == sizeof(CryptoSignSK));
  STATIC_CHECK(sizeof(CryptoSeed) == sizeof(CryptoSignSeed));

  return sodium_init();
}

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
