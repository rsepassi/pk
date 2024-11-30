#include "libbase58.h"
#include "unity.h"
#include "log.h"
#include "stdtypes.h"
#include "sodium.h"

#include <stdlib.h>

static void bytes_from_hex(Str s, u8* out, u8 n) {
  CHECK(s.len == (n * 2));
  sodium_hex2bin(out, n, (char*)s.buf, s.len, 0, 0, 0);
}

static bool libb58_sha256_impl(void* out, const void* msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}

void test_b58(void) {
  b58_sha256_impl = libb58_sha256_impl;

  // Hex string encodes 1-byte version + payload
  Str hex = Str("165a1fc5dd9e6f03819fca94a2d89669469667f9a0");
  u8 bin[21];
  CHECK(sizeof(bin) * 2 == hex.len);
  bytes_from_hex(hex, bin, sizeof(bin));
  LOGB(BytesArray(bin));

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
  LOGB(Bytes(bin2, bin2_len - 4));
  CHECK0(memcmp(bin2, bin, bin2_len - 4));

  // b58check returns the version byte
  CHECK(b58check(bin2, bin2_len, b58, b58_len) == 0x16);
}


void setUp(void) {}
void tearDown(void) {}
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_b58);
  return UNITY_END();
}
