#include "x3dh.h"

#include "log.h"

#define X3DH_KDF_PREFIX "000000000000000000000000pksignal"

typedef struct {
  CryptoKxTx* session_key;
  CryptoKxPK* eph_key;
} X3DHInit;

X3DH_Status x3dh_keys_init(const CryptoSignSK* identity, X3DHKeys* keys) {
  *keys = (X3DHKeys){0};

  keys->sec.identity = identity;
  keys->pub.identity = &identity->pk;

  // Short-term keypair
  if (crypto_kx_keypair((u8*)&keys->pub.shortterm, (u8*)&keys->sec.shortterm))
    return 1;

  // Sign short-term key
  if (crypto_sign_ed25519_detached((u8*)&keys->pub.shortterm_sig, 0,
                                   (u8*)&keys->pub.shortterm,
                                   sizeof(CryptoKxPK), (u8*)identity))
    return 1;

  return 0;
}

// Alice -> Bob
static u8 x3dh_init_internal(const X3DHKeys* A, const X3DHPublic* B,
                             X3DHInit* out) {
  // Alice verifies Bob's pre-shared key
  if (crypto_sign_ed25519_verify_detached(
          (u8*)&B->shortterm_sig, (u8*)&B->shortterm, sizeof(CryptoKxPK),
          (u8*)B->identity  // public key
          ))
    return 1;

  // Alice ephemeral keypair
  CryptoKxSK A_eph_sk;
  if (crypto_kx_keypair((u8*)out->eph_key, (u8*)&A_eph_sk))
    return 1;

  CryptoKxKeypair A_kx;
  if (crypto_sign_ed25519_pk_to_curve25519((u8*)&A_kx.pk, (u8*)A->pub.identity))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8*)&A_kx.sk, (u8*)A->sec.identity))
    return 1;

  CryptoKxPK B_kx;
  if (crypto_sign_ed25519_pk_to_curve25519((u8*)&B_kx, (u8*)B->identity))
    return 1;

  CryptoKxTx dh1;  // DH1 = DH(IK_A, SPK_B)
  CryptoKxTx dh2;  // DH2 = DH(EK_A, IK_B)
  CryptoKxTx dh3;  // DH3 = DH(EK_A, SPK_B)
  if (crypto_kx_client_session_keys(0, (u8*)&dh1, (u8*)&A_kx.pk, (u8*)&A_kx.sk,
                                    (u8*)&B->shortterm))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh2, (u8*)out->eph_key,
                                    (u8*)&A_eph_sk, (u8*)&B_kx))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh3, (u8*)out->eph_key,
                                    (u8*)&A_eph_sk, (u8*)&B->shortterm))
    return 1;

  // Alice computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provides forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)X3DH_KDF_PREFIX,
                                            sizeof(X3DH_KDF_PREFIX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)out->session_key))
    return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&A_eph_sk, sizeof(CryptoKxSK));

  return 0;
}

// Bob <- Alice
static u8 x3dh_init_recv_internal(const X3DHKeys* B, const X3DHHeader* A,
                                  CryptoKxTx* out) {
  // Bob checks that the right shortterm key was used
  // memcmp OK: public key
  u8 sth[X3DH_HSZ];
  if (crypto_generichash_blake2b(sth, sizeof(sth), (u8*)&B->pub.shortterm,
                                 sizeof(B->pub.shortterm), 0, 0))
    return 1;
  if (memcmp(sth, (u8*)&A->shortterm, sizeof(CryptoKxTx)))
    return 1;

  u8 A_kx[sizeof(A->identity)];
  if (crypto_sign_ed25519_pk_to_curve25519(A_kx, (u8*)&A->identity))
    return 1;

  CryptoKxKeypair B_kx;
  if (crypto_sign_ed25519_pk_to_curve25519((u8*)&B_kx.pk, (u8*)B->pub.identity))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8*)&B_kx.sk, (u8*)B->sec.identity))
    return 1;

  CryptoKxTx dh1;  // DH1 = DH(SPK_B, IK_A)
  CryptoKxTx dh2;  // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3;  // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8*)&dh1, (u8*)&B->pub.shortterm,
                                    (u8*)&B->sec.shortterm, A_kx))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh2, (u8*)&B_kx.pk, (u8*)&B_kx.sk,
                                    (u8*)&A->ephemeral))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh3, (u8*)&B->pub.shortterm,
                                    (u8*)&B->sec.shortterm, (u8*)&A->ephemeral))
    return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)X3DH_KDF_PREFIX,
                                            sizeof(X3DH_KDF_PREFIX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)out))
    return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));

  return 0;
}

X3DH_Status x3dh_init(const X3DHKeys* A, const X3DHPublic* B,
                      X3DHHeader* header, X3DH* out) {
  // Derive session key
  X3DHInit A_x3dh_init = {
      .session_key = &out->key,
      .eph_key = &header->ephemeral,
  };
  if (x3dh_init_internal(A, B, &A_x3dh_init))
    return 1;

  header->identity = *A->pub.identity;
  if (crypto_generichash_blake2b(header->shortterm, sizeof(header->shortterm),
                                 (u8*)&B->shortterm, sizeof(B->shortterm), 0,
                                 0))
    return 1;

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8*)A->pub.identity, sizeof(*A->pub.identity));
  memcpy(out->ad + sizeof(*A->pub.identity), (u8*)B->identity,
         sizeof(*B->identity));

  return 0;
}

X3DH_Status x3dh_init_recv(const X3DHKeys* B, const X3DHHeader* header,
                           X3DH* out) {
  // Derive session key
  if (x3dh_init_recv_internal(B, header, &out->key))
    return 1;

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8*)&header->identity, sizeof(*B->pub.identity));
  memcpy(out->ad + sizeof(*B->pub.identity), (u8*)B->pub.identity,
         sizeof(*B->pub.identity));

  return 0;
}
