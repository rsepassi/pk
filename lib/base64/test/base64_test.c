#include "base64.h"
#include "log.h"
#include "unity.h"

#include <stdlib.h>

void test_b64(void) {
  Str a = Str("hello world!");

  Str enc;
  {
    usize sz = base64_encoded_maxlen(a.len);
    enc      = (Str){sz, malloc(sz)};
  }

  CHECK0(base64_encode(a, &enc));
  LOGS(enc);

  Str dec;
  {
    usize sz = base64_decoded_maxlen(enc.len);
    dec      = (Str){sz, malloc(sz)};
  }

  CHECK0(base64_decode(enc, &dec));
  LOGS(dec);

  CHECK(str_eq(a, dec));

  free(enc.buf);
  free(dec.buf);
}

void setUp(void) {}
void tearDown(void) {}
int  main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_b64);
  return UNITY_END();
}
