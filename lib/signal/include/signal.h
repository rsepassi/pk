// An implementation of x3dh and double ratchet using libsodium
//
// X3DH
// Specification: https://signal.org/docs/specifications/x3dh/x3dh.pdf
// Parameters:
//   curve = x25519
//   hash = sha-256
//   info = SignalXos
//   Encode(PK) = libsodium's encoding
//
// Double Ratchet
// Specification:
// https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
// Parameters:
//   GENERATE_DH = Curve25519
//   DH = X25519
//   KDF = HKDF-SHA-256
//   AEAD = ChaCha20-Poly1305
//
// The libary does no dynamic memory allocation.
//
// To allow for arbitrary-sized associated data without dynamic memory
// allocation, AD is replaced with BLAKE2b(CONCAT(AD, header)) instead of
// CONCAT(AD, header) directly.
//
// See copies of specification pdfs in doc/
#pragma once

#include "crypto.h"

#define SIGNAL_APP_ID "SignalXos"

typedef int Signal_Status;
#define SIGNAL_OK 0

// X3DH
// ============================================================================

typedef struct {
  const CryptoSignPK *identity;
  CryptoKxPK kx;
  CryptoKxPK kx_prekey;
  CryptoSig kx_prekey_sig;
} X3DHPublic;

typedef struct {
  CryptoKxSK kx;
  CryptoKxSK kx_prekey;
} X3DHSecret;

typedef struct {
  const CryptoSignSK *identity;
  X3DHPublic pub;
  X3DHSecret sec;
} X3DHKeys;

typedef struct __attribute__((packed)) {
  CryptoAuthTag tag;
  CryptoSignPK identity;
  CryptoKxPK kx_eph;
  CryptoKxPK kx_prekey_B;
} X3DHHeader;

typedef struct {
  CryptoKxTx key;
  u8 ad[sizeof(CryptoSignPK) * 2];
} X3DH;

// Creates X3DHKeys suitable for X3DH given an identity key
Signal_Status x3dh_keys_init(const CryptoSignSK *identity, X3DHKeys *keys);

// A -> B
Signal_Status x3dh_init(const X3DHKeys *A, const X3DHPublic *B,
                        X3DHHeader *header, X3DH *out);
Signal_Status x3dh_init_recv(const X3DHKeys *B, const X3DHHeader *header,
                             X3DH *out);

// Double Ratchet
// ============================================================================

#define SIGNAL_DRAT_CHAIN_SZ 32
#define SIGNAL_DRAT_MAX_SKIP 256

typedef struct {
  CryptoKxPK pk;
  u64 number;
} DratSkipKey;

typedef struct {
  DratSkipKey key;
  CryptoKxTx mk;
} DratSkipEntry;

typedef struct {
  CryptoKxKeypair key;
  CryptoKxPK remote_key;
  u8 root_key[SIGNAL_DRAT_CHAIN_SZ];
  u8 chain_send[SIGNAL_DRAT_CHAIN_SZ];
  u8 chain_recv[SIGNAL_DRAT_CHAIN_SZ];
  u64 send_n;
  u64 recv_n;
  u64 psend_n;
  u8 skip_key[crypto_shorthash_siphash24_KEYBYTES];
  DratSkipEntry skips[SIGNAL_DRAT_MAX_SKIP * 2];
  bool chain_recv_exists;
} DratState;

typedef struct __attribute__((packed)) {
  CryptoKxPK ratchet;
  u64 psend_n;
  u64 number;
  CryptoAuthTag tag;
} DratHeader;

typedef struct {
  CryptoKxTx *session_key;
  CryptoKxPK *pk;
  CryptoKxSK *sk;
} DratInit;

typedef struct {
  CryptoKxTx *session_key;
  CryptoKxPK *bob;
} DratInitRecv;

Signal_Status drat_init(DratState *state, const DratInit *init);
Signal_Status drat_init_recv(DratState *state, const DratInitRecv *init);
usize drat_encrypt_len(usize msg_len);
Signal_Status drat_encrypt(DratState *state, Bytes msg, Bytes ad,
                           DratHeader *header, Bytes *cipher);
Signal_Status drat_decrypt(DratState *state, const DratHeader *header,
                           Bytes cipher, Bytes ad);
