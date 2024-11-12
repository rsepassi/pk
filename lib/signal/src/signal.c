#include "signal.h"

#include "log.h"

// A variant of X3DH where we use 32 0x30 bytes plus an ascii string
// identifying the application as initial input to the KDF
#define KDF_PREFIX "00000000000000000000000000000000pubsignal"

typedef struct {
  CryptoKxTx session_key;
  CryptoKxPK eph_key;
} X3DHInit;

Signal_Status x3dh_keys_seed(const CryptoSeed *seed, X3DHKeys *keys) {
  // Identity key
  if (crypto_sign_seed_keypair((u8 *)&keys->pub.sign, (u8 *)&keys->sec.sign,
                               (u8 *)seed))
    return 1;

  // sk = seed || pk
  DCHECK(sodium_memcmp((u8 *)&keys->sec.sign.seed, (u8 *)seed,
                       sizeof(CryptoSeed)) == 0);
  DCHECK(sodium_memcmp((u8 *)&keys->sec.sign.pk, (u8 *)&keys->pub.sign,
                       sizeof(CryptoSignPK)) == 0);

  // sign -> kx
  if (crypto_sign_ed25519_pk_to_curve25519((u8 *)&keys->pub.kx,
                                           (u8 *)&keys->pub.sign))
    return 1;
  if (crypto_sign_ed25519_sk_to_curve25519((u8 *)&keys->sec.kx,
                                           (u8 *)&keys->sec.sign))
    return 1;

  // Pre-shared keypair
  if (crypto_kx_keypair((u8 *)&keys->pub.kx_preshare,
                        (u8 *)&keys->sec.kx_preshare))
    return 1;

  // Sign pre-shared key
  if (crypto_sign_detached((u8 *)&keys->pub.kx_preshare_sig, 0, // signature
                           (u8 *)&keys->pub.kx_preshare,
                           sizeof(CryptoKxPK),   // input message
                           (u8 *)&keys->sec.sign // signing key
                           ))
    return 1;

  return 0;
}

// Alice -> Bob
static u8 x3dh_init_internal(const X3DHKeys *A, const X3DHPublic *B,
                             X3DHInit *out) {
  // Alice verifies Bob's pre-shared key
  if (crypto_sign_verify_detached((u8 *)&B->kx_preshare_sig,
                                  (u8 *)&B->kx_preshare, sizeof(CryptoKxPK),
                                  (u8 *)&B->sign // public key
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
                                    (u8 *)&A->sec.kx, (u8 *)&B->kx_preshare))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8 *)&dh2, (u8 *)&out->eph_key,
                                    (u8 *)&A_eph_sk, (u8 *)&B->kx))
    return 1;
  if (crypto_kx_client_session_keys(0, (u8 *)&dh3, (u8 *)&out->eph_key,
                                    (u8 *)&A_eph_sk, (u8 *)&B->kx_preshare))
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
  if (sodium_memcmp((u8 *)&B->pub.kx_preshare, (u8 *)&A->kx_prekey_B,
                    sizeof(CryptoKxTx)))
    return 1;

  u8 A_kx[sizeof(A->sign)];
  if (crypto_sign_ed25519_pk_to_curve25519(A_kx, (u8 *)&A->sign))
    return 1;

  CryptoKxTx dh1; // DH1 = DH(SPK_B, IK_A)
  CryptoKxTx dh2; // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3; // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8 *)&dh1, (u8 *)&B->pub.kx_preshare,
                                    (u8 *)&B->sec.kx_preshare, A_kx))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8 *)&dh2, (u8 *)&B->pub.kx,
                                    (u8 *)&B->sec.kx, (u8 *)&A->kx_eph))
    return 1;
  if (crypto_kx_server_session_keys(0, (u8 *)&dh3, (u8 *)&B->pub.kx_preshare,
                                    (u8 *)&B->sec.kx_preshare,
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

static u8 x3dh_init_parse(const Str msg, X3DHHeader **header, Str *ciphertxt) {
  if (msg.len < sizeof(X3DHHeader))
    return 1;
  *header = (X3DHHeader *)(msg.buf);
  ciphertxt->len = msg.len - sizeof(X3DHHeader);
  ciphertxt->buf = msg.buf + sizeof(X3DHHeader);

  if (msg.len != sizeof(X3DHHeader) + (*header)->ciphertxt_len)
    return 1;

  return 0;
}

u64 x3dh_init_len(u64 plaintxt_len) {
  u64 ciphertxt_len = plaintxt_len;
  return sizeof(X3DHHeader) + ciphertxt_len;
}

Signal_Status x3dh_init(const X3DHKeys *A, const X3DHPublic *B,
                        const Str plaintxt, Str *out, CryptoKxTx *session_key) {
  if (out->len != x3dh_init_len(plaintxt.len))
    return 1;

  X3DHInit A_x3dh_init;
  if (x3dh_init_internal(A, B, &A_x3dh_init))
    return 1;

  // Fill header
  X3DHHeader *header = (X3DHHeader *)out->buf;
  header->sign = A->pub.sign;
  header->kx_eph = A_x3dh_init.eph_key;
  header->kx_prekey_B = B->kx_preshare;
  header->ciphertxt_len = out->len - sizeof(X3DHHeader);

  // AD = IK_A || IK_B
  u8 keys[sizeof(A->pub.sign) * 2];
  memcpy(keys, (u8 *)&A->pub.sign, sizeof(A->pub.sign));
  memcpy(keys + sizeof(A->pub.sign), (u8 *)&B->sign, sizeof(A->pub.sign));

  // AEAD
  u8 *ciphertxt = out->buf + sizeof(X3DHHeader);
  u8 nonce[crypto_box_NONCEBYTES] = {0};
  if (crypto_aead_chacha20poly1305_encrypt_detached(
          ciphertxt, (u8 *)&header->tag, 0, plaintxt.buf, plaintxt.len, keys,
          sizeof(keys), 0, nonce, (u8 *)&A_x3dh_init.session_key))
    return 1;

  *session_key = A_x3dh_init.session_key;

  return 0;
}

Signal_Status x3dh_init_recv(const X3DHKeys *B, Str msg, Str *ciphertxt,
                             CryptoKxTx *session_key) {
  X3DHHeader *header;
  if (x3dh_init_parse(msg, &header, ciphertxt))
    return 1;

  if (x3dh_init_recv_internal(B, header, session_key))
    return 1;

  // AD = IK_A || IK_B
  u8 keys[sizeof(B->pub.sign) * 2];
  memcpy(keys, (u8 *)&header->sign, sizeof(B->pub.sign));
  memcpy(keys + sizeof(B->pub.sign), (u8 *)&B->pub.sign, sizeof(B->pub.sign));

  // AEAD decrypt
  u8 nonce[crypto_box_NONCEBYTES] = {0};
  if (crypto_aead_chacha20poly1305_decrypt_detached(
          ciphertxt->buf, 0, ciphertxt->buf, ciphertxt->len, (u8 *)&header->tag,
          keys, sizeof(keys), nonce, (u8 *)session_key))
    return 1;

  return 0;
}
