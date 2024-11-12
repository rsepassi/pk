#include "signal.h"

#include "log.h"

// A variant of X3DH where we use 32 0x30 bytes plus an ascii string
// identifying the application as initial input to the KDF
#define KDF_PREFIX "00000000000000000000000000000000pubsignal"

typedef struct {
  CryptoKxTx session_key;
  CryptoKxPK eph_key;
} X3DHInit;

Signal_Status x3dh_keys_init(const CryptoSignSK *identity, X3DHKeys *keys) {
  keys->identity = identity;
  keys->pub.identity = &identity->pk;

  // sign -> kx
  if (crypto_sign_ed25519_pk_to_curve25519((u8 *)&keys->pub.kx,
                                           (u8 *)&identity->pk))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8 *)&keys->sec.kx,
                                           (u8 *)identity))
    return 1;

  // Pre-shared keypair
  if (crypto_kx_keypair((u8 *)&keys->pub.kx_prekey,
                        (u8 *)&keys->sec.kx_prekey))
    return 1;

  // Sign pre-shared key
  if (crypto_sign_detached((u8 *)&keys->pub.kx_prekey_sig, 0, // signature
                           (u8 *)&keys->pub.kx_prekey,
                           sizeof(CryptoKxPK),   // input message
                           (u8 *)identity // signing key
                           ))
    return 1;

  return 0;
}

// Alice -> Bob
static u8 x3dh_init_internal(const X3DHKeys *A, const X3DHPublic *B,
                             X3DHInit *out) {
  // Alice verifies Bob's pre-shared key
  if (crypto_sign_verify_detached((u8 *)&B->kx_prekey_sig,
                                  (u8 *)&B->kx_prekey, sizeof(CryptoKxPK),
                                  (u8 *)B->identity // public key
                                  ))
    return 1;

  // Alice ephemeral keypair
  CryptoKxSK A_eph_sk;
  if (crypto_kx_keypair((u8 *)&out->eph_key, (u8 *)&A_eph_sk))
    return 1;

  CryptoKxTx dh1; // DH1 = DH(IK_A, SPK_B)
  CryptoKxTx dh2; // DH2 = DH(EK_A, IK_B)
  CryptoKxTx dh3; // DH3 = DH(EK_A, SPK_B)
  if (crypto_kx_client_session_keys(0, (u8 *)&dh1, (u8 *)&A->pub.kx,
                                    (u8 *)&A->sec.kx, (u8 *)&B->kx_prekey))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8 *)&dh2, (u8 *)&out->eph_key,
                                    (u8 *)&A_eph_sk, (u8 *)&B->kx))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8 *)&dh3, (u8 *)&out->eph_key,
                                    (u8 *)&A_eph_sk, (u8 *)&B->kx_prekey))
    return 1;

  // Alice computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provides forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8 *)"x", 0))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)KDF_PREFIX,
                                            sizeof(KDF_PREFIX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8 *)&out->session_key))
    return 1;

  // Erase unneded information
  sodium_memzero((u8 *)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8 *)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8 *)&dh3, sizeof(CryptoKxTx));
  sodium_memzero((u8 *)&A_eph_sk, sizeof(CryptoKxSK));

  return 0;
}

// Bob <- Alice
static u8 x3dh_init_recv_internal(const X3DHKeys *B, const X3DHHeader *A,
                                  CryptoKxTx *out) {
  // Bob checks that the right prekey was used
  if (sodium_memcmp((u8 *)&B->pub.kx_prekey, (u8 *)&A->kx_prekey_B,
                    sizeof(CryptoKxTx)))
    return 1;

  u8 A_kx[sizeof(A->identity)];
  if (crypto_sign_ed25519_pk_to_curve25519(A_kx, (u8 *)&A->identity))
    return 1;

  CryptoKxTx dh1; // DH1 = DH(SPK_B, IK_A)
  CryptoKxTx dh2; // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3; // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8 *)&dh1, (u8 *)&B->pub.kx_prekey,
                                    (u8 *)&B->sec.kx_prekey, A_kx))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8 *)&dh2, (u8 *)&B->pub.kx,
                                    (u8 *)&B->sec.kx, (u8 *)&A->kx_eph))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8 *)&dh3, (u8 *)&B->pub.kx_prekey,
                                    (u8 *)&B->sec.kx_prekey,
                                    (u8 *)&A->kx_eph))
    return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8 *)"x", 0))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)KDF_PREFIX,
                                            sizeof(KDF_PREFIX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8 *)out))
    return 1;

  // Erase unneded information
  sodium_memzero((u8 *)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8 *)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8 *)&dh3, sizeof(CryptoKxTx));

  return 0;
}

Signal_Status x3dh_init(const X3DHKeys *A, const X3DHPublic *B,
                        X3DHHeader *header, X3DH *out) {
  // Derive session key
  X3DHInit A_x3dh_init;
  if (x3dh_init_internal(A, B, &A_x3dh_init))
    return 1;
  out->key = A_x3dh_init.session_key;

  // Fill header
  header->identity = *A->pub.identity;
  header->kx_eph = A_x3dh_init.eph_key;
  header->kx_prekey_B = B->kx_prekey;

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8 *)A->pub.identity, sizeof(*A->pub.identity));
  memcpy(out->ad + sizeof(*A->pub.identity), (u8 *)B->identity, sizeof(*A->pub.identity));

  return 0;
}

Signal_Status x3dh_init_recv(const X3DHKeys *B, const X3DHHeader *header,
                             X3DH *out) {
  // Derive session key
  if (x3dh_init_recv_internal(B, header, &out->key))
    return 1;

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8 *)&header->identity, sizeof(*B->pub.identity));
  memcpy(out->ad + sizeof(*B->pub.identity), (u8 *)B->pub.identity, sizeof(*B->pub.identity));

  return 0;
}

// Drat: Double Ratchet
//
// Bob -> Alice current ratchet public key
// Alice runs DH with APK to get DHO
// Alice sends APK to Bob
// Bob runs DH with APK to get DHO2
//
// DH outputs at each step are used to derive new send/recv chain keys
// Bob's sending chain = Alice's receiving chain, and vice-versa
//
// Drat step updates KDF root chain twice to derive
// 1. send and 2. recv chain key
//
// Combining the symmetric-key and DH ratchets gives the Double Ratchet
// 1. When a message is sent or received, a symmetric-key ratchet step is
//    applied to the sending or receiving chain to derive the message key.
// 2. When a new ratchet public key is received, a DH ratchet step is performed
//    prior to the symmetric-key ratchet to replace the chain keys.
//
// #define MAX_SKIP 512
// MKSKIPPED: Dictionary of skipped-over message keys, indexed by ratchet
// public key and message number. Raises an exception if too many elements
// are stored.
//
//
// x3dh inputs
// * X3DH.key becomes SK input to DR initialization
// * X3DH.ad becomes the AD input to DR encryption and decryption
// * kx_prekey becomes Bob's initial rachet keypair for DR initialization
