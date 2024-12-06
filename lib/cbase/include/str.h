#pragma once

#include "log.h"
#include "stdmacros.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  size_t   len;
  uint8_t* buf;
} Bytes;

// Str is just another name for Bytes
typedef Bytes Str;

// Convenience constructors
#define Str(s)          ((Str){STRLEN((s)), (uint8_t*)(s)})
#define Str0(s)         ((Str){strlen((s)), (uint8_t*)(s)})
#define BytesZero       ((Bytes){0, 0})
#define Bytes(b, l)     ((Bytes){(l), (uint8_t*)(b)})
#define BytesArray(arr) ((Bytes){sizeof(arr), (uint8_t*)(arr)})
#define BytesObj(obj)   ((Bytes){sizeof(obj), (uint8_t*)&(obj)})

static inline bool str_eq(Str a, Str b) {
  if (a.len != b.len)
    return false;
  for (size_t i = 0; i < a.len; ++i) {
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
  CHECK(dst->len >= src.len);
  dst->len = src.len;
  memcpy(dst->buf, src.buf, src.len);
}
