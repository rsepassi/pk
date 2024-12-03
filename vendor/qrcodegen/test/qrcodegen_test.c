#include "qrcodegen.h"

#include <string.h>

#include "unity.h"

static void test_qrcode() {
	const char *text = "https://peer2.xyz?key=4jiHX7c7FMaBAAKXH4QN3TKHHH1NR77J3sUncdh2Nuvba9dfmp";
	uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
	TEST_ASSERT(qrcodegen_ez_encode((uint8_t*)text, strlen(text), qrcode));
	qrcodegen_console_print(stdout, qrcode);
}

void setUp(void) {}
void tearDown(void) {}
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_qrcode);
  return UNITY_END();
}
