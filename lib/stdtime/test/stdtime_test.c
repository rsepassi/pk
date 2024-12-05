#include "log.h"
#include "stdtime.h"
#include "unity.h"

void test_stdtime(void) {
  i64 now = stdtime_now_secs();

  char ts_buf[STDTIME_RFC3339_UTC_TIMESTAMP_LEN];
  Str  ts = BytesArray(ts_buf);

  stdtime_rfc3339_utc_format(ts, now);
  LOGS(ts);

  i64 now2;
  CHECK0(stdtime_rfc3339_utc_parse(ts, &now2));

  CHECK(now == now2);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_stdtime);
  return UNITY_END();
}
