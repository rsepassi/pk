#pragma once

#include "stdmacros.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  uint64_t len;
  uint8_t* buf;
} Str;

typedef Str Bytes;
#define BytesZero ((Bytes){0, 0})

#define Str(s)      ((Str){STRLEN((s)), (u8*)(s)})
#define Bytes(b, l) ((Str){(l), (u8*)(b)})

static inline Str str_from_c(const char* buf) {
  return (Str){.len = strlen(buf), .buf = (uint8_t*)buf};
}

#define BytesArray(arr) ((Bytes){sizeof(arr), (u8*)(arr)})
#define BytesObj(obj)   ((Bytes){sizeof(obj), (u8*)&(obj)})

static inline bool str_eq(Str a, Str b) {
  if (a.len != b.len)
    return false;
  for (uint64_t i = 0; i < a.len; ++i) {
    if (a.buf[i] != b.buf[i])
      return false;
  }
  return true;
}

static inline bool str_startswith(Str s, Str prefix) {
  if (s.len < prefix.len)
    return false;
  return memcmp(s.buf, prefix.buf, prefix.len) == 0;
}

static inline void bytes_copy(Bytes* dst, Bytes src) {
  dst->len = src.len;
  memcpy(dst->buf, src.buf, src.len);
}
