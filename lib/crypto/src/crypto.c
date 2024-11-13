#include "crypto.h"

#include "log.h"

u8 crypto_init() {
  // sanity checks
  STATIC_CHECK(crypto_sign_ed25519_SECRETKEYBYTES == sizeof(CryptoSignSK));
  STATIC_CHECK(sizeof(CryptoSeed) == sizeof(CryptoSignSeed));

  return sodium_init();
}
