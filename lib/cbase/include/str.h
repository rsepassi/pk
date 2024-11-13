#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  uint64_t len;
  uint8_t *buf;
} Str;

typedef Str Bytes;
#define BytesZero ((Bytes){0, 0})

static inline Str str_from_c(char *buf) {
  return (Str){.len = strlen(buf), .buf = (uint8_t *)buf};
}

static inline bool str_eq(Str a, Str b) {
  if (a.len != b.len)
    return false;
  for (uint64_t i = 0; i < a.len; ++i) {
    if (a.buf[i] != b.buf[i])
      return false;
  }
  return true;
}
