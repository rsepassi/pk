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
//
// See copies of pdfs in doc/
//
// TODO:
// * One-time prekeys, or alternative anti-replay mechanism
// * Consider adding PQXDH: https://signal.org/docs/specifications/pqxdh/
#pragma once

#include "crypto.h"

#define SIGNAL_APP_ID "SignalXos"

typedef int Signal_Status;
#define SIGNAL_OK 0

// X3DH
// ============================================================================

typedef struct {
  const CryptoSignPK* identity;
  CryptoKxPK kx;
  CryptoKxPK kx_prekey;
  CryptoSig kx_prekey_sig;
} X3DHPublic;

typedef struct {
  CryptoKxSK kx;
  CryptoKxSK kx_prekey;
} X3DHSecret;

typedef struct {
  const CryptoSignSK* identity;
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

typedef struct {
  CryptoKxKeypair key;
  CryptoKxPK remote_key;
  u8 root_key[32];
  u8 chain_send[32];
  u8 chain_recv[32];
  u64 send_n;
  u64 recv_n;
  u64 chain_len;
  CryptoKxTx header_key_send;
  CryptoKxTx header_key_recv;
  CryptoKxTx next_header_key_send;
  CryptoKxTx next_header_key_recv;
} DratState;

typedef struct __attribute__((packed)) {
  CryptoKxTx ratchet;
  u64 number;
  u64 chain_len;
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
