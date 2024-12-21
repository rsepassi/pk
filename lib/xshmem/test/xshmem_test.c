#include "log.h"
#include "stdtypes.h"
#include "unity.h"
#include "xshmem.h"

void test_xshmem(void) { CHECK(true); }

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_xshmem);
  return UNITY_END();
}
