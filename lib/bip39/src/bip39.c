#include "bip39.h"

#include "sodium.h"
#include "stdmacros.h"

typedef struct {
  Bytes bytes;
  Bytes hash;
  usize biti;
} BytesIter;

typedef struct {
  u16* words;
  usize wordi;
  usize biti;
} WordsIter;

static inline u8 bytes_next_bit(BytesIter* it) {
  usize bytei = it->biti / 8;
  usize bytebiti = it->biti % 8;
  u8* buf;
  if (bytei >= it->bytes.len) {
    buf = it->hash.buf;
    bytei -= it->bytes.len;
  } else {
    buf = it->bytes.buf;
  }
  u8 bit = BITGET(buf[bytei], bytebiti);
  it->biti++;
  return bit;
}

static inline void bytes_set_next_bit(BytesIter* it, u8 b) {
  usize bytei = it->biti / 8;
  usize bytebiti = it->biti % 8;
  u8* buf;
  if (bytei >= it->bytes.len) {
    buf = it->hash.buf;
    bytei -= it->bytes.len;
  } else {
    buf = it->bytes.buf;
  }
  if (bytebiti == 0)
    buf[bytei] = 0;
  if (b)
    buf[bytei] = BITSET(buf[bytei], bytebiti);
  it->biti++;
}

static inline void words_advance(WordsIter* it) {
  it->biti++;
  if (it->biti == 11) {
    it->biti = 0;
    it->wordi++;
  }
}

static inline u8 words_next_bit(WordsIter* it) {
  u16 word_bytes = it->words[it->wordi];
  u8 bit = BITGET(word_bytes, it->biti);
  words_advance(it);
  return bit;
}

static inline void words_set_next_bit(WordsIter* it, u8 b) {
  u16* word_bytes = &it->words[it->wordi];
  if (it->biti == 0)
    *word_bytes = 0;

  if (b)
    *word_bytes = BITSET(*word_bytes, it->biti);

  words_advance(it);
}

int bip39_mnemonic_idxs(Bytes b, u16* out) {
  if (b.len % 4 != 0 || b.len < 16)
    return 1;

  u8 h[crypto_hash_sha256_BYTES];
  if (crypto_hash_sha256(h, b.buf, b.len))
    return 1;

  usize nwords = bip39_MNEMONIC_LEN(b.len);
  usize nbits = nwords * 11;

  BytesIter src = {b, BytesArray(h), 0};
  WordsIter dst = {out, 0, 0};

  for (usize i = 0; i < nbits; ++i)
    words_set_next_bit(&dst, bytes_next_bit(&src));

  return 0;
}

int bip39_mnemonic_bytes(u16* words, usize words_len, Bytes* out) {
  if (out->len != bip39_BYTE_LEN(words_len))
    return 1;

  u8 wordh[crypto_hash_sha256_BYTES];

  WordsIter src = {words, 0, 0};
  BytesIter dst = {*out, BytesArray(wordh), 0};

  usize nbits = words_len * 11;
  for (usize i = 0; i < nbits; ++i)
    bytes_set_next_bit(&dst, words_next_bit(&src));

  u8 h[crypto_hash_sha256_BYTES];
  if (crypto_hash_sha256(h, out->buf, out->len))
    return 1;

  usize nhbits = (out->len * 8) / 32;
  for (usize i = 0; i < nhbits; ++i) {
    usize bytei = i / 8;
    u8 bytebiti = i % 8;
    if (BITGET(h[bytei], bytebiti) != BITGET(wordh[bytei], bytebiti))
      return 1;
  }
  return 0;
}
