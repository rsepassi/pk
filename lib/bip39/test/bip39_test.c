#include "bip39.h"
#include "log.h"
#include "sodium.h"
#include "unity.h"

static void test_bip39(void) {
  // Generate 32 bytes of entropy
  u8 key_buf[32];
  randombytes_buf(key_buf, sizeof(key_buf));
  Bytes key = {sizeof(key_buf), key_buf};
  LOGB(key);

  // Convert it to a word list
  u16 word_idxs[bip39_MNEMONIC_LEN(sizeof(key_buf))];
  CHECK0(bip39_mnemonic_idxs(key, word_idxs));
  for (usize i = 0; i < ARRAY_LEN(word_idxs); ++i) {
    LOG("%02d. %04d %s", (int)(i + 1), word_idxs[i], bip39_words[word_idxs[i]]);
  }

  // Verify that it decodes properly
  u8 dec_buf[sizeof(key_buf)];
  Bytes dec = {sizeof(key_buf), dec_buf};
  CHECK0(bip39_mnemonic_bytes(word_idxs, ARRAY_LEN(word_idxs), &dec));
  CHECK0(memcmp(key_buf, dec_buf, sizeof(key_buf)));

  // From mnemonic to seed:
  // Password Hash: Argon2id (Bitcoin uses PBKDF2)
  // Password = joined mnemonic words
  // Salt = "mnemonic" + passphrase
}

void setUp(void) {}
void tearDown(void) {}
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_bip39);
  return UNITY_END();
}
