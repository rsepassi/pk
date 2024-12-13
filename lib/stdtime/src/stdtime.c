#include "stdtime.h"

#include "log.h"
#include "uv.h"

#include <time.h>

#define MS_PER_S  1000
#define NS_PER_MS 1000000

static i64 utc_offset_secs(void) {
  time_t    t  = stdtime_now_secs();
  struct tm tm = {0};
  gmtime_r(&t, &tm);
  tm.tm_isdst = -1;
  time_t t2   = mktime(&tm);
  return t - t2;
}

i64 stdtime_now_secs(void) {
  uv_timespec64_t time;
  uv_clock_gettime(UV_CLOCK_REALTIME, &time);
  return time.tv_sec;
}

i64 stdtime_now_ms(void) {
  uv_timespec64_t time;
  uv_clock_gettime(UV_CLOCK_MONOTONIC, &time);
  return time.tv_sec * MS_PER_S + time.tv_nsec / NS_PER_MS;
}

i64 stdtime_now_monotonic_secs(void) {
  uv_timespec64_t time;
  uv_clock_gettime(UV_CLOCK_MONOTONIC, &time);
  return time.tv_sec;
}

i64 stdtime_now_monotonic_ms(void) {
  uv_timespec64_t time;
  uv_clock_gettime(UV_CLOCK_MONOTONIC, &time);
  return time.tv_sec * MS_PER_S + time.tv_nsec / NS_PER_MS;
}

void stdtime_rfc3339_utc_format(Bytes ts, i64 epoch_secs) {
  CHECK(ts.len == STDTIME_RFC3339_UTC_TIMESTAMP_LEN);
  const time_t sec = epoch_secs;
  struct tm    tm  = {0};
  gmtime_r(&sec, &tm);
  strftime((char*)ts.buf, ts.len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void stdtime_rfc3339_utc_now(Bytes ts) {
  stdtime_rfc3339_utc_format(ts, stdtime_now_secs());
}

int stdtime_rfc3339_utc_parse(Bytes ts, i64* epoch_secs) {
  CHECK(ts.len == STDTIME_RFC3339_UTC_TIMESTAMP_LEN);
  struct tm tm = {0};
  int       year, month, day, hour, minute, second;
  if (sscanf((char*)ts.buf, "%d-%d-%dT%d:%d:%dZ", &year, &month, &day, &hour,
             &minute, &second) != 6) {
    return 1;
  }

  tm.tm_year  = year - 1900;
  tm.tm_mon   = month - 1;
  tm.tm_mday  = day;
  tm.tm_hour  = hour;
  tm.tm_min   = minute;
  tm.tm_sec   = second;
  *epoch_secs = mktime(&tm) + utc_offset_secs();
  return 0;
}
