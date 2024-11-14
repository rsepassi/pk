#include "base64.h"

#include "log.h"

#define PAD '='
u8 b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
u8 b64_dec[] = {
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, // 0 - 15
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, // 16 - 31
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 62, 99, 99, 99, 63, // 32 - 47
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 99, 99, 99, 64, 99, 99, // 48 - 63
    99, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, // 64 - 79
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 99, 99, 99, 99, 99, // 99 - 96
    99, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 87 - 111
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 99, 99, 99, 99, 99  // 112 - 127
};

usize base64_encoded_maxlen(usize in_len) {
  if (in_len == 0)
    return 0;
  return in_len * 4 / 3 + 4;
}

usize base64_decoded_maxlen(usize in_len) {
  if (in_len == 0)
    return 0;
  return in_len * 3 / 4;
}

Base64_Status base64_encode(Bytes in, Bytes *out) {
  if (out->len < base64_encoded_maxlen(in.len))
    return 1;
  if (in.len == 0)
    return 0;

  usize nchunks = in.len / 3;
  u64 j = 0;
  for (u64 i = 0; i < nchunks; ++i) {
    u64 k = i * 3;
    u8 a = in.buf[k];
    u8 b = in.buf[k + 1];
    u8 c = in.buf[k + 2];

    out->buf[j++] = b64_chars[a >> 2];
    out->buf[j++] = b64_chars[((a & 0x03) << 4) + (b >> 4)];
    out->buf[j++] = b64_chars[((b & 0x0f) << 2) + (c >> 6)];
    out->buf[j++] = b64_chars[c & 0x3f];
  }

  usize rem = in.len % 3;
  if (rem == 1) {
    u8 a = in.buf[in.len - 1];
    out->buf[j++] = b64_chars[a >> 2];
    out->buf[j++] = b64_chars[(a & 0x03) << 4];
    out->buf[j++] = PAD;
    out->buf[j++] = PAD;
  } else if (rem == 2) {
    u8 a = in.buf[in.len - 2];
    u8 b = in.buf[in.len - 1];
    out->buf[j++] = b64_chars[a >> 2];
    out->buf[j++] = b64_chars[((a & 0x03) << 4) + (b >> 4)];
    out->buf[j++] = b64_chars[(b & 0x0f) << 2];
    out->buf[j++] = PAD;
  }

  out->len = j;

  return 0;
}

Base64_Status base64_decode(Bytes in, Bytes *out) {
  if (in.len % 4 != 0)
    return 1;
  if (out->len < base64_decoded_maxlen(in.len))
    return 1;
  if (in.len == 0)
    return 0;

  usize nchunks = in.len / 4;
  bool padded = in.buf[in.len - 1] == PAD;
  if (padded)
    nchunks--;

  u64 j = 0;
  for (usize i = 0; i < nchunks; ++i) {
    u64 k = i * 4;
    u8 a = b64_dec[in.buf[k]];
    u8 b = b64_dec[in.buf[k + 1]];
    u8 c = b64_dec[in.buf[k + 2]];
    u8 d = b64_dec[in.buf[k + 3]];

    out->buf[j++] = (a << 2) | ((b & 0xf0) >> 4);
    out->buf[j++] = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
    out->buf[j++] = ((c & 0x03) << 6) | (d & 0x3f);
  }

  if (padded) {
    u64 k = nchunks * 4;
    usize npad = in.buf[in.len - 2] == PAD ? 2 : 1;
    if (npad == 2) {
      u8 a = b64_dec[in.buf[k]];
      u8 b = b64_dec[in.buf[k + 1]];
      out->buf[j++] = a << 2 | ((b & 0xf0) >> 4);
    } else if (npad == 1) {
      u8 a = b64_dec[in.buf[k]];
      u8 b = b64_dec[in.buf[k + 1]];
      u8 c = b64_dec[in.buf[k + 2]];
      out->buf[j++] = a << 2 | ((b & 0xf0) >> 4);
      out->buf[j++] = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
    }
  }

  out->len = j;

  return 0;
}
