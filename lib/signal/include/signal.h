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
// Specification: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
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

typedef struct {
  CryptoSignPK sign;
  CryptoKxPK kx;
  CryptoKxPK kx_preshare;
  CryptoSig kx_preshare_sig;
} X3DHPublic;

typedef struct {
  CryptoSignSK sign;
  CryptoKxSK kx;
  CryptoKxSK kx_preshare;
} X3DHSecret;

typedef struct {
  X3DHPublic pub;
  X3DHSecret sec;
} X3DHKeys;

typedef struct __attribute__((packed)) {
  CryptoAuthTag tag;
  CryptoSignPK sign;
  CryptoKxPK kx_eph;
  CryptoKxPK kx_prekey_B;
  u64 ciphertxt_len;
} X3DHHeader;

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

// Creates X3DHKeys suitable for X3DH given a seed
Signal_Status x3dh_keys_seed(const CryptoSeed *seed, X3DHKeys *keys);

// A -> B
u64 x3dh_init_len(u64 plaintxt_len);
Signal_Status x3dh_init(const X3DHKeys *A, const X3DHPublic *B,
                        const Str plaintxt, Str *ciphertxt,
                        CryptoKxTx *session_key);
Signal_Status x3dh_init_recv(const X3DHKeys *B, Str msg, Str *plaintxt,
                             CryptoKxTx *session_key);
