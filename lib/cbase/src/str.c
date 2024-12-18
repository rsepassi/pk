#include "str.h"

#include <stdint.h>

int int_from_str(int64_t* out, Str s) {
  if (s.len == 0)
    return 1;

  uint8_t* p   = s.buf;
  size_t   len = s.len;
#define ADVANCE()                                                              \
  do {                                                                         \
    ++p;                                                                       \
    --len;                                                                     \
  } while (0)

  bool negate = false;
  if (*p == '-') {
    negate = true;
    ADVANCE();
  } else if (*p == '+') {
    ADVANCE();
  }

  int base = 10;
  if (len >= 2) {
    if (memcmp(p, "0x", 2) == 0) {
      base = 16;
      ADVANCE();
      ADVANCE();
    } else if (memcmp(p, "0b", 2) == 0) {
      base = 2;
      ADVANCE();
      ADVANCE();
    } else if (memcmp(p, "0o", 2) == 0) {
      base = 8;
      ADVANCE();
      ADVANCE();
    }
  }

  if (len == 0)
    return 1;

  *out = 0;
  while (len) {
    if (*p == '_') {
      ADVANCE();
      continue;
    }

    char start = '0';
    char end   = (char)(start + base - 1);

    uint8_t place = 0;

    if (base == 16) {
      if (*p >= start && *p <= end)
        place = (uint8_t)(*p - start);
      else if (*p >= 'a' && *p <= 'f')
        place = *p - 'a' + 10;
      else if (*p >= 'A' && *p <= 'F')
        place = *p - 'A' + 10;
      else
        return 1;
    } else {
      if (*p < start || *p > end)
        return 1;
      place = (uint8_t)(*p - start);
    }

    *out = *out * base + place;

    ADVANCE();
  }

  if (negate)
    *out = -(*out);

#undef ADVANCE

  return 0;
}
