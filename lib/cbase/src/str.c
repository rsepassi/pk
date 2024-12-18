#include "str.h"

#include "log.h"

#include <float.h>
#include <math.h>
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

int float_from_str(double* out, Str s) {
  *out = 0;

  if (s.len == 0)
    return 1;

  Str ldec_str = {0};
  {
    size_t i = 0;
    for (; i < s.len; ++i) {
      uint8_t c = s.buf[i];
      if (c == '.' || c == 'e' || c == 'E')
        break;
    }
    if (i == 0)
      return 1;

    ldec_str = bytes_advance(&s, i);
  }

  Str    rdec_str    = {0};
  size_t rdec_places = 0;
  {
    if (s.len && s.buf[0] == '.') {
      bytes_advance(&s, 1);
      size_t i = 0;
      for (; i < s.len; ++i) {
        uint8_t c = s.buf[i];
        if (c == 'e' || c == 'E')
          break;
        if (c != '_')
          rdec_places++;
      }
      rdec_str = bytes_advance(&s, i);
    }
  }

  Str exp_str = {0};
  {
    if (s.len && (s.buf[0] == 'e' || s.buf[0] == 'E')) {
      bytes_advance(&s, 1);
      exp_str = s;
    }
  }

  int64_t ldec_i;
  if (int_from_str(&ldec_i, ldec_str))
    return 1;
  double ldec_d = (double)ldec_i;

  int64_t rdec_i = 0;
  if (rdec_str.len)
    if (int_from_str(&rdec_i, rdec_str))
      return 1;
  if (rdec_places > DBL_MAX_10_EXP)
    return 1;
  if (rdec_i < 0)
    return 1;
  double rdec_d = (double)rdec_i / pow(10.0, (double)(rdec_places));

  int64_t exp_i   = 0;
  bool    neg_exp = false;
  if (exp_str.len)
    if (int_from_str(&exp_i, exp_str))
      return 1;
  if (exp_i < 0) {
    if (exp_i < DBL_MIN_10_EXP)
      return 1;
    neg_exp = true;
    exp_i   = -exp_i;
  } else {
    if (exp_i > DBL_MAX_10_EXP)
      return 1;
  }
  double exp_d = pow(10.0, (double)exp_i);

  *out = (ldec_d + rdec_d);
  if (exp_i) {
    if (neg_exp)
      *out /= exp_d;
    else
      *out *= exp_d;
  }

  if (isinf(*out))
    return 1;
  if (isnan(*out))
    return 1;

  return 0;
}
