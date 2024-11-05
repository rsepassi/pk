#pragma once

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_PREFIX_(level, fd) do { \
  fprintf(fd, "%s[%s %s:%d] ", #level, log_get_current_time(), __FILENAME__, __LINE__ ); \
} while(0)
#define LOG_(level, fd, fmt, ...) do { \
  LOG_PREFIX_(level, fd); \
  fprintf(fd, fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LOG(fmt, ...) LOG_(I, stderr, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_(E, stderr, fmt, ##__VA_ARGS__)
#define LOGS(s) LOG("%s=%.*s", #s, (int)(s).len, (s).buf)
#define LOGB(b) do { \
  LOG_PREFIX_(I, stderr); \
  fprinthex(stderr, #b, b.buf, b.len); \
  fprintf(stderr, "\n"); \
} while (0)

#define CHECK_(x, fmt, ...) do { \
    if (!(x)) { LOG("check failed: (%s) " fmt, #x, ##__VA_ARGS__); exit(1); } \
    } while (0)
#define CHECK(x, ...) CHECK_(x, "" __VA_ARGS__)
#define CHECK0(x, ...) CHECK(((x) == 0), ##__VA_ARGS__)

#ifdef DEBUG
#define DCHECK(x, ...) CHECK(x, ##__VA_ARGS__)
#define DLOG(fmt, ...) LOG_(D, stderr, fmt, ##__VA_ARGS__)
#else
#define DCHECK(x, ...)
#define DLOG(fmt, ...)
#endif

#define STATIC_CHECK(x) (void)sizeof(char[ (x) ? 1 : -1 ])

char* log_get_current_time();
void fprinthex(FILE* stream, char *tag, uint8_t *b, uint64_t len);
