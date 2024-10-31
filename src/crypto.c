#include "crypto.h"

#include "log.h"

// A variant of X3DH where we use 32 0x30 bytes plus an ascii string
// identifying the application as initial input to the KDF
#define KDF_PREFIX "00000000000000000000000000000000pubsignal"

u8 crypto_init() {
  // Various sanity checks
  STATIC_CHECK(sizeof(CryptoSeed) == sizeof(CryptoSignSeed));
  STATIC_CHECK(crypto_sign_SECRETKEYBYTES == sizeof(CryptoSignSK));
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretbox_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_secretbox_MACBYTES == 16);
  STATIC_CHECK(crypto_secretstream_xchacha20poly1305_KEYBYTES == sizeof(CryptoKxTx));
  STATIC_CHECK(crypto_scalarmult_curve25519_BYTES == crypto_sign_ed25519_PUBLICKEYBYTES);
  STATIC_CHECK(sizeof(CryptoSignPK) == sizeof(CryptoKxPK));

  return sodium_init();
}

u8 crypto_seed_new_user(const CryptoSeed* seed, CryptoUserState* user) {
  // Identity key
  if (crypto_sign_seed_keypair((u8*)&user->pub.sign, (u8*)&user->sec.sign, (u8*)seed)) return 1;

  // sk = seed + pk
  DCHECK(sodium_memcmp((u8*)&user->sec.sign.seed, (u8*)seed, sizeof(CryptoSeed)) == 0);
  DCHECK(sodium_memcmp((u8*)&user->sec.sign.pk, (u8*)&user->pub.sign, sizeof(CryptoSignPK)) == 0);

  // Identity kx key
  if (crypto_kx_seed_keypair((u8*)&user->pub.kx, (u8*)&user->sec.kx, (u8*)seed)) return 1;

  // Pre-shared keypair
  if (crypto_kx_keypair((u8*)&user->pub.kx_preshare, (u8*)&user->sec.kx_preshare)) return 1;

  // Sign kx key
  if (crypto_sign_detached(
        (u8*)&user->pub.kx_sig, 0,  // signature
        (u8*)&user->pub.kx, sizeof(CryptoKxPK),  // input message
        (u8*)&user->sec.sign  // signing key
        )) return 1;

  // Sign pre-shared key
  if (crypto_sign_detached(
        (u8*)&user->pub.kx_preshare_sig, 0,  // signature
        (u8*)&user->pub.kx_preshare, sizeof(CryptoKxPK),  // input message
        (u8*)&user->sec.sign  // signing key
        )) return 1;

  return 0;
}

// Alice -> Bob
static u8 crypto_x3dh_initiate(const CryptoUserState* A, const CryptoUserPState* B, CryptoX3DHInit* out) {
  // Alice verifies Bob's kx key
  if (crypto_sign_verify_detached(
        (u8*)&B->kx_sig,
        (u8*)&B->kx, sizeof(CryptoKxPK),
        (u8*)&B->sign  // public key
        )) return 1;

  // Alice verifies Bob's pre-shared key
  if (crypto_sign_verify_detached(
        (u8*)&B->kx_preshare_sig,
        (u8*)&B->kx_preshare, sizeof(CryptoKxPK),
        (u8*)&B->sign  // public key
        )) return 1;

  // Alice ephemeral keypair
  CryptoKxSK A_eph_sk;
  if (crypto_kx_keypair((u8*)&out->eph_key, (u8*)&A_eph_sk)) return 1;

  CryptoKxTx dh1;  // DH1 = DH(IK_A, SPK_B)
  CryptoKxTx dh2;  // DH2 = DH(EK_A, IK_B)
  CryptoKxTx dh3;  // DH3 = DH(EK_A, SPK_B)
  if (crypto_kx_client_session_keys(0, (u8*)&dh1, (u8*)&A->pub.kx, (u8*)&A->sec.kx, (u8*)&B->kx_preshare)) return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh2, (u8*)&out->eph_key, (u8*)&A_eph_sk, (u8*)&B->kx)) return 1;
  if (crypto_kx_client_session_keys(0, (u8*)&dh3, (u8*)&out->eph_key, (u8*)&A_eph_sk, (u8*)&B->kx_preshare)) return 1;

  // Alice computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3(+DH4, with a one-time prekey) provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0)) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)KDF_PREFIX, sizeof(KDF_PREFIX))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)&out->session_key)) return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&A_eph_sk, sizeof(CryptoKxSK));

  return 0;
}

// Bob <- Alice
static u8 crypto_x3dh_reply(const CryptoUserState* B, const CryptoX3DHFirstMessageHeaderAuth* A, CryptoKxTx* out) {
  // Bob checks that the message is intended for him
  if (sodium_memcmp((u8*)&B->pub.kx, (u8*)&A->kx_B, sizeof(CryptoKxTx))) return 1;
  // Bob checks that the right prekey was used
  if (sodium_memcmp((u8*)&B->pub.kx_preshare, (u8*)&A->kx_prekey_B, sizeof(CryptoKxTx))) return 1;

  // Bob verifies Alices's kx key
  if (crypto_sign_verify_detached(
        (u8*)&A->kx_sig,
        (u8*)&A->kx, sizeof(CryptoKxPK),
        (u8*)&A->sign  // public key
        )) return 1;

  CryptoKxTx dh1;  // DH1 = DH(SPK_B, IK_A)
  CryptoKxTx dh2;  // DH2 = DH(IK_B, EK_A)
  CryptoKxTx dh3;  // DH3 = DH(SPK_B, EK_A)
  if (crypto_kx_server_session_keys(0, (u8*)&dh1, (u8*)&B->pub.kx_preshare, (u8*)&B->sec.kx_preshare, (u8*)&A->kx)) return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh2, (u8*)&B->pub.kx, (u8*)&B->sec.kx, (u8*)&A->kx_eph)) return 1;
  if (crypto_kx_server_session_keys(0, (u8*)&dh3, (u8*)&B->pub.kx_preshare, (u8*)&B->sec.kx_preshare, (u8*)&A->kx_eph)) return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3(+DH4, with a one-time prekey) provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8*)"x", 0)) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)KDF_PREFIX, sizeof(KDF_PREFIX))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh1, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh2, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8*)&dh3, sizeof(CryptoKxTx))) return 1;
  if (crypto_kdf_hkdf_sha256_extract_final(&kdf_state, (u8*)out)) return 1;

  // Erase unneded information
  sodium_memzero((u8*)&dh1, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh2, sizeof(CryptoKxTx));
  sodium_memzero((u8*)&dh3, sizeof(CryptoKxTx));

  return 0;
}

u64 crypto_x3dh_first_msg_len(u64 plaintxt_len) {
  u64 ciphertxt_len = plaintxt_len + crypto_secretstream_xchacha20poly1305_ABYTES;
  return sizeof(CryptoX3DHFirstMessageHeader) + ciphertxt_len;
}

u8 crypto_x3dh_first_msg(const CryptoUserState* A, const CryptoUserPState* B, const Str plaintxt, Str* out) {
  if (out->len != crypto_x3dh_first_msg_len(plaintxt.len)) return 1;

  CryptoX3DHInit A_x3dh_init;
  CHECK(crypto_x3dh_initiate(A, B, &A_x3dh_init) == 0);

  // Fill header
  CryptoX3DHFirstMessageHeader* header = (CryptoX3DHFirstMessageHeader*)out->buf;
  header->ciphertxt_len = out->len - sizeof(CryptoX3DHFirstMessageHeader);
  header->auth.sign = A->pub.sign;
  header->auth.kx = A->pub.kx;
  header->auth.kx_sig = A->pub.kx_sig;
  header->auth.kx_eph = A_x3dh_init.eph_key;
  header->auth.kx_B = B->kx;
  header->auth.kx_prekey_B = B->kx_preshare;

  u8* ciphertxt = out->buf + sizeof(CryptoX3DHFirstMessageHeader);

  crypto_secretstream_xchacha20poly1305_state state;
  if (crypto_secretstream_xchacha20poly1305_init_push(&state, header->header, (u8*)&A_x3dh_init.session_key)) return 1;
  if (crypto_secretstream_xchacha20poly1305_push(
      &state,
      ciphertxt, NULL,
      plaintxt.buf, plaintxt.len,
      (u8*)&header->auth, sizeof(CryptoX3DHFirstMessageHeaderAuth),
      crypto_secretstream_xchacha20poly1305_TAG_FINAL)) return 1;
  return 0;
}

u8 crypto_x3dh_first_msg_parse(const Str msg, CryptoX3DHFirstMessageHeader** header, Str* ciphertxt) {
  if (msg.len < sizeof(CryptoX3DHFirstMessageHeader)) return 1;
  *header = (CryptoX3DHFirstMessageHeader*)(msg.buf);
  ciphertxt->len = (*header)->ciphertxt_len;
  ciphertxt->buf = msg.buf + sizeof(CryptoX3DHFirstMessageHeader);

  if (msg.len != sizeof(CryptoX3DHFirstMessageHeader) + ciphertxt->len) return 1;
  if (ciphertxt->len < crypto_secretstream_xchacha20poly1305_ABYTES) return 1;

  return 0;
}

u64 crypto_plaintxt_len(u64 ciphertxt_len) {
  return ciphertxt_len - crypto_secretstream_xchacha20poly1305_ABYTES;
}

u8 crypto_x3dh_first_msg_recv(const CryptoUserState* B, const CryptoX3DHFirstMessageHeader* header, Str ciphertxt, Str* plaintxt) {
  if (plaintxt->len != crypto_plaintxt_len(ciphertxt.len)) return 1;
  CryptoKxTx B_x3dh_session_key;
  if (crypto_x3dh_reply(B, &header->auth, &B_x3dh_session_key)) return 1;
  crypto_secretstream_xchacha20poly1305_state state;
  if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header->header, (u8*)&B_x3dh_session_key)) return 1;

  u8 tag;
  if (crypto_secretstream_xchacha20poly1305_pull(&state, plaintxt->buf, 0, &tag, ciphertxt.buf, ciphertxt.len, (u8*)&header->auth, sizeof(CryptoX3DHFirstMessageHeaderAuth))) return 1;
  if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) return 1;
  return 0;
}

