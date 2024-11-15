#include "log.h"

#include <inttypes.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

char* log_get_current_time() {
  static char time_str[13];

#ifdef _WIN32
  SYSTEMTIME st;
  GetSystemTime(&st);

  snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d.%03d", st.wHour,
           st.wMinute, st.wSecond, st.wMilliseconds);
#else
  struct timeval tv;
  struct tm* tm_info;

  gettimeofday(&tv, NULL);
  tm_info = gmtime(&tv.tv_sec);

  snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d.%03d", tm_info->tm_hour,
           tm_info->tm_min, tm_info->tm_sec, (int)(tv.tv_usec / 1000));
#endif

  return time_str;
}

void fprinthex(FILE* stream, char* tag, uint8_t* b, uint64_t len) {
  fprintf(stream, "%s(%" PRIu64 ")=", tag, len);
  for (uint64_t i = 0; i < len; ++i)
    fprintf(stream, "%02X", b[i]);
}
