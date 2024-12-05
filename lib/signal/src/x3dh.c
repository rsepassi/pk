#include "x3dh.h"

#include "log.h"

#define X3DH_KDF_CTX "pksignal"

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
X3DH_Status x3dh_init(const X3DHKeys* A, const X3DHPublic* B,
                      X3DHHeader* header, X3DH* out) {
  // Alice verifies Bob's short-term key
  if (crypto_sign_ed25519_verify_detached((u8*)&B->shortterm_sig,
                                          (u8*)&B->shortterm,
                                          sizeof(CryptoKxPK), (u8*)B->identity))
    return 1;

  // Alice ephemeral keypair
  CryptoKxPK* eph_key = &header->ephemeral;
  CryptoKxSK  A_eph_sk;
  if (crypto_kx_keypair((u8*)eph_key, (u8*)&A_eph_sk))
    return 1;

  // ed25519 -> x25519
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
  if (crypto_kx_client_session_keys(0, (u8*)&dh2, (u8*)eph_key, (u8*)&A_eph_sk,
                                    (u8*)&B_kx))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh3, (u8*)eph_key, (u8*)&A_eph_sk,
                                    (u8*)&B->shortterm))
    return 1;

  // Alice computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provides forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  crypto_kdf_hkdf_sha256_state kdf0_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)X3DH_KDF_CTX,
                                          STRLEN(X3DH_KDF_CTX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  memcpy(&kdf0_state, &kdf_state, sizeof(kdf_state));
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)&out->key))
    return 1;

  // The header key is KDF(DH2 || DH3)
  CryptoKxTx header_key;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf0_state, (u8*)&header_key))
    return 1;

  // Fill and encrypt header
  header->identity  = *A->pub.identity;
  header->shortterm = B->shortterm;
  {
    u8 zero_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            (u8*)&header->identity, (u8*)&header->header_tag, 0,
            (u8*)&header->identity,
            sizeof(header->identity) + sizeof(header->shortterm), 0, 0, 0,
            zero_nonce, (u8*)&header_key))
      return 1;
  }

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&A_eph_sk, sizeof(CryptoKxSK));

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8*)A->pub.identity, sizeof(*A->pub.identity));
  memcpy(out->ad + sizeof(*A->pub.identity), (u8*)B->identity,
         sizeof(*B->identity));

  return 0;
}

// Bob <- Alice
X3DH_Status x3dh_init_recv(const X3DHKeys* B, const X3DHHeader* A, X3DH* out) {
  // ed25519 -> x25519
  CryptoKxKeypair B_kx;
  if (crypto_sign_ed25519_pk_to_curve25519((u8*)&B_kx.pk, (u8*)B->pub.identity))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8*)&B_kx.sk, (u8*)B->sec.identity))
    return 1;

  // Compute DH2 and DH3 with the plaintext ephemeral key
  CryptoKxTx dh2;  // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3;  // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8*)&dh2, (u8*)&B_kx.pk, (u8*)&B_kx.sk,
                                    (u8*)&A->ephemeral))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh3, (u8*)&B->pub.shortterm,
                                    (u8*)&B->sec.shortterm, (u8*)&A->ephemeral))
    return 1;

  // Derive header key KDF(DH2 || DH3)
  CryptoKxTx                   header_key;
  crypto_kdf_hkdf_sha256_state kdf_state;
  crypto_kdf_hkdf_sha256_state kdf0_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf0_state, (u8*)X3DH_KDF_CTX,
                                          STRLEN(X3DH_KDF_CTX)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf0_state, (u8*)&dh2,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf0_state, (u8*)&dh3,
                                            sizeof(CryptoKxTx)))
    return 1;
  memcpy(&kdf_state, &kdf0_state, sizeof(kdf_state));
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf0_state, (u8*)&header_key))
    return 1;

  // Decrypt header
  {
    u8 zero_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            (u8*)&A->identity, 0, (u8*)&A->identity,
            sizeof(A->identity) + sizeof(A->shortterm), (u8*)&A->header_tag, 0,
            0, zero_nonce, (u8*)&header_key))
      return 1;
  }

  // Bob checks that the right shortterm key was used
  // memcmp OK: public key
  if (memcmp((u8*)&B->pub.shortterm, (u8*)&A->shortterm, sizeof(CryptoKxTx)))
    return 1;

  u8 A_kx[sizeof(A->identity)];
  if (crypto_sign_ed25519_pk_to_curve25519(A_kx, (u8*)&A->identity))
    return 1;

  CryptoKxTx dh1;  // DH1 = DH(SPK_B, IK_A)
  if (crypto_kx_server_session_keys(0, (u8*)&dh1, (u8*)&B->pub.shortterm,
                                    (u8*)&B->sec.shortterm, A_kx))
    return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provide forward secrecy
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1,
                                            sizeof(CryptoKxTx)))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)&out->key))
    return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8*)&A->identity, sizeof(*B->pub.identity));
  memcpy(out->ad + sizeof(*B->pub.identity), (u8*)B->pub.identity,
         sizeof(*B->pub.identity));

  return 0;
}
