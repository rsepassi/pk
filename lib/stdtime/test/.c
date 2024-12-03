#include "log.h"
#include "stdtime.h"
#include "unity.h"

void test_stdtime(void) { CHECK(true); }

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_stdtime);
  return UNITY_END();
}
