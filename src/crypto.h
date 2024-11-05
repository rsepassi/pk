#pragma once

#include "sodium.h"

#include "stdtypes.h"

typedef struct {
  u8 bytes[32];
} CryptoSeed;

typedef struct {
  u8 bytes[crypto_sign_SEEDBYTES];
} CryptoSignSeed;
typedef struct {
  u8 bytes[crypto_sign_PUBLICKEYBYTES];
} CryptoSignPK;
typedef struct {
  CryptoSignSeed seed;
  CryptoSignPK pk;
} CryptoSignSK;
typedef struct {
  u8 bytes[crypto_sign_BYTES];
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
  u8 bytes[crypto_secretbox_MACBYTES];
} CryptoAuthTag;

#define CryptoBytes(x) ((Bytes){sizeof(x), (u8 *)&(x)})

// X3DH first draft
// ============================================================================

typedef struct {
  CryptoSignPK sign;
  CryptoKxPK kx;
  CryptoSig kx_sig;
  CryptoKxPK kx_preshare;
  CryptoSig kx_preshare_sig;
} CryptoUserPState;

typedef struct {
  CryptoSignSK sign;
  CryptoKxSK kx;
  CryptoKxSK kx_preshare;
} CryptoUserSState;

typedef struct {
  CryptoUserPState pub;
  CryptoUserSState sec;
} CryptoUserState;

typedef struct {
  CryptoKxTx session_key;
  CryptoKxPK eph_key;
} CryptoX3DHInit;

typedef struct {
  CryptoSignPK sign;
  CryptoKxPK kx;
  CryptoSig kx_sig;
  CryptoKxPK kx_eph;
  CryptoKxPK kx_B;
  CryptoKxPK kx_prekey_B;
} CryptoX3DHFirstMessageHeaderAuth;

typedef struct {
  u8 header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  CryptoX3DHFirstMessageHeaderAuth auth;
  u64 ciphertxt_len;
} CryptoX3DHFirstMessageHeader;

// Initializes libsodium and do some checks
u8 crypto_init(void);

// Creates a CryptoUserState suitable for X3DH given a seed
u8 crypto_seed_new_user(const CryptoSeed *seed, CryptoUserState *user);

// How long a plaintxt buffer needs to be for a given ciphertxt len
u64 crypto_plaintxt_len(u64 ciphertxt_len);

// A -> B
u64 crypto_x3dh_first_msg_len(u64 plaintxt_len);
u8 crypto_x3dh_first_msg(const CryptoUserState *A, const CryptoUserPState *B,
                         const Str plaintxt, Str *out);

// B <- A
u8 crypto_x3dh_first_msg_parse(const Str msg,
                               CryptoX3DHFirstMessageHeader **header,
                               Str *ciphertxt);
u8 crypto_x3dh_first_msg_recv(const CryptoUserState *B,
                              const CryptoX3DHFirstMessageHeader *header,
                              Str ciphertxt, Str *plaintxt);
