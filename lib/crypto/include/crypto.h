// Type-safe struct wrappers around libsodium byte-sizes
#pragma once

#include "sodium.h"

#include "stdtypes.h"

typedef struct {
  u8 bytes[32];
} CryptoSeed;

typedef struct {
  u8 bytes[crypto_sign_ed25519_SEEDBYTES];
} CryptoSignSeed;
typedef struct {
  u8 bytes[crypto_sign_ed25519_PUBLICKEYBYTES];
} CryptoSignPK;
typedef struct __attribute__((packed)) {
  CryptoSignSeed seed;
  CryptoSignPK pk;
} CryptoSignSK;
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
  u8 bytes[crypto_secretbox_KEYBYTES];
} CryptoBoxKey;
typedef struct {
  u8 bytes[crypto_secretbox_MACBYTES];
} CryptoAuthTag;

#define CryptoBytes(x) ((Bytes){sizeof(x), (u8 *)&(x)})

// Initializes libsodium and does some checks
u8 crypto_init(void);
