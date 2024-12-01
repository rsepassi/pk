// X3DH
// Specification: https://signal.org/docs/specifications/x3dh/x3dh.pdf
// Parameters:
//   curve = x25519
//   hash = sha-256
//   info = pksignal
#pragma once

#include "crypto.h"

typedef enum {
  X3DH_OK = 0,
  X3DH_Err,
  X3DH_ErrFailedVerify,
} X3DH_Status;

typedef struct {
  const CryptoSignPK* identity;
  CryptoKxPK shortterm;
  CryptoSig shortterm_sig;
} X3DHPublic;

typedef struct {
  const CryptoSignSK* identity;
  CryptoKxSK shortterm;
} X3DHSecret;

typedef struct {
  X3DHPublic pub;
  X3DHSecret sec;
} X3DHKeys;

typedef struct __attribute__((packed)) {
  CryptoKxPK ephemeral;   // plaintext
  CryptoSignPK identity;  // encrypted
  CryptoKxPK shortterm;   // encrypted
  CryptoAuthTag header_tag;
} X3DHHeader;

typedef struct {
  CryptoKxTx key;
  u8 ad[sizeof(CryptoSignPK) * 2];
} X3DH;

// Creates X3DHKeys suitable for X3DH given an identity key
X3DH_Status x3dh_keys_init(const CryptoSignSK* identity, X3DHKeys* keys);

// A -> B
X3DH_Status x3dh_init(const X3DHKeys* A, const X3DHPublic* B,
                      X3DHHeader* header, X3DH* out);
// B <- A
X3DH_Status x3dh_init_recv(const X3DHKeys* B, const X3DHHeader* header,
                           X3DH* out);
