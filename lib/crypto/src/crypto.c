#include "crypto.h"

#include "log.h"

u8 crypto_init() {
  // Various sanity checks
  STATIC_CHECK(crypto_sign_SECRETKEYBYTES == sizeof(CryptoSignSK));

  // TODO: move these to where they actually are used
  STATIC_CHECK(crypto_secretstream_xchacha20poly1305_KEYBYTES ==
               sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretbox_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(sizeof(CryptoSeed) == sizeof(CryptoSignSeed));
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretbox_MACBYTES == 16);
  STATIC_CHECK(crypto_scalarmult_curve25519_BYTES ==
               crypto_sign_ed25519_PUBLICKEYBYTES);
  STATIC_CHECK(sizeof(CryptoSignPK) == sizeof(CryptoKxPK));

  return sodium_init();
}
