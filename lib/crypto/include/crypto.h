// Type-safe struct wrappers around libsodium byte-sizes
#pragma once

#include "sodium.h"
#include "stdtypes.h"

typedef struct {
  u8 bytes[crypto_sign_ed25519_SEEDBYTES];
} CryptoSignSeed;
typedef struct {
  u8 bytes[crypto_sign_ed25519_PUBLICKEYBYTES];
} CryptoSignPK;
typedef struct __attribute__((packed)) {
  CryptoSignSeed seed;
  CryptoSignPK   pk;
} CryptoSignSK;
typedef struct {
  CryptoSignPK pk;
  CryptoSignSK sk;
} CryptoSignKeypair;
typedef struct {
  u8 bytes[crypto_sign_ed25519_BYTES];
} CryptoSig;

typedef struct {
  u8 bytes[crypto_kx_SEEDBYTES];
} CryptoKxSeed;
typedef struct {
  u8 bytes[crypto_kx_PUBLICKEYBYTES];
} CryptoKxPK;
typedef struct {
  u8 bytes[crypto_kx_SECRETKEYBYTES];
} CryptoKxSK;
typedef struct {
  CryptoKxPK pk;
  CryptoKxSK sk;
} CryptoKxKeypair;
typedef struct {
  u8 bytes[crypto_kx_SESSIONKEYBYTES];
} CryptoKxTx;

typedef struct {
  u8 bytes[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
} CryptoBoxKey;
typedef struct {
  u8 bytes[crypto_aead_chacha20poly1305_IETF_ABYTES];
} CryptoAuthTag;

#define CryptoBytes(x) ((Bytes){sizeof(x), (u8*)&(x)})

typedef struct {
  Allocator base;
} CryptoAllocator;
Allocator allocator_crypto(CryptoAllocator* base);

int CryptoSignPK_parsehex(CryptoSignPK* pk, Bytes hex);
int CryptoSignSK_parsehex(CryptoSignSK* sk, Bytes hex);
