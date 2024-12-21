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
#define Str0(s)         ((Str){strlen((char*)(s)), (uint8_t*)(s)})
#define BytesZero       ((Bytes){0, 0})
#define Bytes(b, l)     ((Bytes){(l), (uint8_t*)(b)})
#define BytesArray(arr) ((Bytes){sizeof(arr), (uint8_t*)(arr)})
#define BytesObj(obj)   ((Bytes){sizeof(obj), (uint8_t*)&(obj)})

#ifdef _WIN32
#define PRIusz "llu"
#else
#define PRIusz "lu"
#endif
#define PRIStr    ".*s"
#define StrPRI(s) (int)(s).len, (s).buf

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

static inline Bytes bytes_peek(Bytes in, size_t step) {
  return Bytes(in.buf, step);
}

static inline Bytes bytes_advance(Bytes* in, size_t step) {
  Bytes out = *in;
  if (step >= in->len) {
    *in = BytesZero;
    return out;
  }

  out.len = step;
  in->buf += step;
  in->len -= step;
  return out;
}

static inline Bytes bytes_write(Bytes* dst, Bytes src) {
  CHECK(dst->len >= src.len);
  Bytes out = bytes_advance(dst, src.len);
  bytes_copy(&out, src);
  return out;
}

int int_from_str(int64_t* out, Str s);
int float_from_str(double* out, Str s);
