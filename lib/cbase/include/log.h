#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __FILENAME__                                                           \
  (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_PREFIX_(level, fd)                                                 \
  do {                                                                         \
    fprintf(fd, "%s[%s %8s:%4d %-16s] ", #level, log_get_current_time(),       \
            __FILENAME__, __LINE__, __func__);                                 \
  } while (0)
#define LOG_(level, fd, fmt, ...)                                              \
  do {                                                                         \
    LOG_PREFIX_(level, fd);                                                    \
    fprintf(fd, fmt "\n", ##__VA_ARGS__);                                      \
  } while (0)

#define LOG(fmt, ...)  LOG_(I, stderr, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_(E, stderr, fmt, ##__VA_ARGS__)
#define LOGS(s)        LOG("%s=%.*s", #s, (int)(s).len, (s).buf)
#define LOGB(b)                                                                \
  do {                                                                         \
    LOG_PREFIX_(I, stderr);                                                    \
    fprinthex(stderr, #b, (b).buf, (b).len);                                   \
    fprintf(stderr, "\n");                                                     \
  } while (0)

#define CHECK_(x, fmt, ...)                                                    \
  do {                                                                         \
    if (!(x)) {                                                                \
      LOG("check failed: (%s) " fmt, #x, ##__VA_ARGS__);                       \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define CHECK(x, ...) CHECK_(x, "" __VA_ARGS__)

#define CHECK0_(x, fmt, ...)                                                   \
  do {                                                                         \
    long __rc = (long)(x);                                                     \
    if (__rc != 0) {                                                           \
      LOG("check failed: (%s), expected 0, got %ld " fmt, #x, __rc,            \
          ##__VA_ARGS__);                                                      \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define CHECK0(x, ...) CHECK0_(x, "" __VA_ARGS__)

#ifdef DEBUG
#define DCHECK(x, ...) CHECK(x, ##__VA_ARGS__)
#define DLOG(fmt, ...) LOG_(D, stderr, fmt, ##__VA_ARGS__)
#else
#define DCHECK(x, ...)
#define DLOG(fmt, ...)
#endif

#define STATIC_CHECK(x) (void)sizeof(char[(x) ? 1 : -1])

char* log_get_current_time();
void  fprinthex(FILE* stream, char* tag, const uint8_t* buf, size_t buf_len);
