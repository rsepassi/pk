#include "coco.h"
#include "log.h"
#include "unity.h"

void test_coco(void) { CHECK(true); }

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_coco);
  return UNITY_END();
}
