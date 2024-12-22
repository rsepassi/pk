#include "stdtime.h"

#include "log.h"

#include <time.h>

#define MS_PER_S  1000
#define NS_PER_MS 1000000

typedef struct {
  int64_t secs;
  int64_t nsecs;
} XTime;

static XTime xclock_gettime(void);
static XTime xclock_gettime_monotonic(void);
static void  xgmtime(const time_t* timer, struct tm* buf);

#ifdef _WIN32

#include <windows.h>

static void xgmtime(const time_t* timer, struct tm* buf) {
  gmtime_s(buf, timer);
}

static XTime xclock_gettime(void) {
  FILETIME       ft;
  ULARGE_INTEGER li;

  // Get current time in FILETIME format
  GetSystemTimeAsFileTime(&ft);

  // Convert FILETIME to ULARGE_INTEGER for easier manipulation
  li.LowPart  = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;

  // Convert Windows FILETIME (100-nanosecond intervals since January 1, 1601)
  // to Unix epoch (seconds since January 1, 1970)
  // First, subtract the difference between 1601 and 1970
  li.QuadPart -= 116444736000000000LL;

  // Calculate seconds and nanoseconds
  XTime out;
  out.secs = li.QuadPart / 10000000LL;  // Convert 100ns to seconds
  out.nsecs =
      (li.QuadPart % 10000000LL) * 100;  // Remaining 100ns intervals to ns

  return out;
}

static XTime xclock_gettime_monotonic(void) {
  static uint64_t frequency = 0;
  if (frequency == 0) {
    LARGE_INTEGER f;
    CHECK(QueryPerformanceFrequency(&f));
    frequency = f.QuadPart;
  }

  LARGE_INTEGER counter;
  CHECK(QueryPerformanceCounter(&counter));

  int64_t secs = counter.QuadPart / frequency;
  // Using double for intermediate calculation to maintain precision
  double remaining = (double)(counter.QuadPart % frequency);

  XTime out;
  out.secs  = secs;
  out.nsecs = (int64_t)((remaining / (double)frequency) * 1000000000);
  return out;
}

#else

static void xgmtime(const time_t* timer, struct tm* buf) {
  gmtime_r(timer, buf);
}

static XTime xclock_gettime(void) {
  struct timespec t;
  int             rc = clock_gettime(CLOCK_REALTIME, &t);
  CHECK0(rc);
  XTime out = {t.tv_sec, t.tv_nsec};
  return out;
}

static XTime xclock_gettime_monotonic(void) {
  struct timespec t;
  int             rc = clock_gettime(CLOCK_MONOTONIC, &t);
  CHECK0(rc);
  XTime out = {t.tv_sec, t.tv_nsec};
  return out;
}

#endif

static i64 utc_offset_secs(void) {
  time_t    t  = stdtime_now_secs();
  struct tm tm = {0};
  xgmtime(&t, &tm);
  tm.tm_isdst = -1;
  time_t t2   = mktime(&tm);
  return t - t2;
}

i64 stdtime_now_secs(void) {
  XTime time = xclock_gettime();
  return time.secs;
}

i64 stdtime_now_ms(void) {
  XTime time = xclock_gettime_monotonic();
  return time.secs * MS_PER_S + time.nsecs / NS_PER_MS;
}

i64 stdtime_now_monotonic_secs(void) {
  XTime time = xclock_gettime_monotonic();
  return time.secs;
}

i64 stdtime_now_monotonic_ms(void) {
  XTime time = xclock_gettime_monotonic();
  return time.secs * MS_PER_S + time.nsecs / NS_PER_MS;
}

i64 stdtime_now_monotonic_ns(void) {
  XTime time = xclock_gettime_monotonic();
  return time.secs * MS_PER_S * NS_PER_MS + time.nsecs;
}

void stdtime_rfc3339_utc_format(Bytes ts, i64 epoch_secs) {
  CHECK(ts.len == STDTIME_RFC3339_UTC_TIMESTAMP_LEN);
  const time_t sec = epoch_secs;
  struct tm    tm  = {0};
  xgmtime(&sec, &tm);
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
