#include "unity.h"

void setUp(void) {
	// set stuff up here
}

void tearDown(void) {
	// clean stuff up here
}

void test_function_should_doBlahAndBlah(void) {
  TEST_ASSERT_TRUE(1);
}

void test_function_should_doAlsoDoBlah(void) {
  TEST_ASSERT_TRUE(1);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_function_should_doBlahAndBlah);
  RUN_TEST(test_function_should_doAlsoDoBlah);
  return UNITY_END();
}
