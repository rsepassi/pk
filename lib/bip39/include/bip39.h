#pragma once

#include "stdtypes.h"

// Number of words to encode sz bytes.
// Inputs are extended with ((sz * 8) / 32) bits of their sha256 hash.
// Each word encodes 11 bits of information.
#define bip39_MNEMONIC_LEN(sz) ((((sz) * 8) + (((sz) * 8) / 32)) / 11)

// Number of bytes nwords encodes.
#define bip39_BYTE_LEN(nwords) (((nwords) * 32) / 24)

// Determines word idxs for the given bytes.
// b.len must be divisible by 4
// out must be of length bip39_MNEMONIC_LEN(b.len)
int bip39_mnemonic_idxs(Bytes b, u16* out);

// Determines bytes for the given words.
int bip39_mnemonic_bytes(u16* words, usize words_len, Bytes* out);

extern const char* bip39_words[2048];
