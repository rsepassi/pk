// Double Ratchet
// Specification:
// https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
// Parameters:
//   GENERATE_DH = Curve25519
//   DH = X25519
//   KDF = HKDF-SHA-256
//   AEAD = ChaCha20-Poly1305
#pragma once

#include "crypto.h"

typedef int Drat_Status;
#define Drat_OK 0

#define DRAT_CHAIN_SZ 32

typedef struct {
  CryptoKxKeypair key;
  CryptoKxPK      bob;
  u8              root_key[DRAT_CHAIN_SZ];
  u8              chain_send[DRAT_CHAIN_SZ];
  u8              chain_recv[DRAT_CHAIN_SZ];
  u64             send_n;
  u64             recv_n;
  u64             psend_n;
} DratState;

typedef struct __attribute__((packed)) {
  CryptoKxPK    key;
  u64           send_n;
  u64           psend_n;
  CryptoAuthTag tag;
} DratHeader;

typedef struct {
  CryptoKxTx* session_key;
  CryptoKxPK* pk;
  CryptoKxSK* sk;
} DratInit;

typedef struct {
  CryptoKxTx* session_key;
  CryptoKxPK* bob;
} DratInitRecv;

Drat_Status drat_init(DratState* state, const DratInit* init);
Drat_Status drat_init_recv(DratState* state, const DratInitRecv* init);
usize       drat_encrypt_len(usize msg_len);
Drat_Status drat_encrypt(DratState* state, Bytes msg, Bytes ad,
                         DratHeader* header, Bytes* cipher);
Drat_Status drat_decrypt(DratState* state, const DratHeader* header,
                         Bytes cipher, Bytes ad);
