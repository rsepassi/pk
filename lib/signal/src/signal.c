#include "signal.h"

#include "log.h"

#define X3DH_KDF_PREFIX "000000000000000000000000pksignal"
#define DRAT_KDF_ROOT "drat-kdf-root"
#define DRAT_KDF_CHAIN "drat-kdf-chain"

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
  if (crypto_sign_ed25519_sk_to_curve25519((u8 *)&keys->sec.kx, (u8 *)identity))
    return 1;

  // Pre-shared keypair
  if (crypto_kx_keypair((u8 *)&keys->pub.kx_prekey, (u8 *)&keys->sec.kx_prekey))
    return 1;

  // Sign pre-shared key
  if (crypto_sign_detached((u8 *)&keys->pub.kx_prekey_sig, 0, // signature
                           (u8 *)&keys->pub.kx_prekey,
                           sizeof(CryptoKxPK), // input message
                           (u8 *)identity      // signing key
                           ))
    return 1;

  return 0;
}

// Alice -> Bob
static u8 x3dh_init_internal(const X3DHKeys *A, const X3DHPublic *B,
                             X3DHInit *out) {
  // Alice verifies Bob's pre-shared key
  if (crypto_sign_verify_detached((u8 *)&B->kx_prekey_sig, (u8 *)&B->kx_prekey,
                                  sizeof(CryptoKxPK),
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
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)X3DH_KDF_PREFIX,
                                            sizeof(X3DH_KDF_PREFIX)))
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
                                    (u8 *)&B->sec.kx_prekey, (u8 *)&A->kx_eph))
    return 1;

  // Bob computes the session key KDF(DH1 || DH2 || DH3)
  // DH1+DH2 provide mutual authentication
  // DH3 provide forward secrecy
  crypto_kdf_hkdf_sha256_state kdf_state;
  if (crypto_kdf_hkdf_sha256_extract_init(&kdf_state, (u8 *)"x", 0))
    return 1;
  if (crypto_kdf_hkdf_sha256_extract_update(&kdf_state, (u8 *)X3DH_KDF_PREFIX,
                                            sizeof(X3DH_KDF_PREFIX)))
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
  memcpy(out->ad + sizeof(*A->pub.identity), (u8 *)B->identity,
         sizeof(*A->pub.identity));

  return 0;
}

Signal_Status x3dh_init_recv(const X3DHKeys *B, const X3DHHeader *header,
                             X3DH *out) {
  // Derive session key
  if (x3dh_init_recv_internal(B, header, &out->key))
    return 1;

  // AD = IK_A || IK_B
  memcpy(out->ad, (u8 *)&header->identity, sizeof(*B->pub.identity));
  memcpy(out->ad + sizeof(*B->pub.identity), (u8 *)B->pub.identity,
         sizeof(*B->pub.identity));

  return 0;
}

static Signal_Status drat_dh(CryptoKxPK *pk, CryptoKxSK *sk, CryptoKxPK *bob,
                             CryptoKxTx *dh) {
  bool isclient = memcmp(pk, bob, sizeof(CryptoKxPK)) < 0;
  if (isclient) {
    if (crypto_kx_client_session_keys(0, (u8 *)dh, (u8 *)pk, (u8 *)sk,
                                      (u8 *)bob))
      return 1;
  } else {
    if (crypto_kx_server_session_keys(0, (u8 *)dh, (u8 *)pk, (u8 *)sk,
                                      (u8 *)bob))
      return 1;
  }
  return 0;
}

static Signal_Status drat_kdf_rk(u8 *rk, CryptoKxTx *dh, u8 *rk_out,
                                 u8 *chain_out) {
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(CryptoKxTx));
  u8 key[crypto_kdf_hkdf_sha256_KEYBYTES];
  if (crypto_kdf_hkdf_sha256_extract(key, rk, sizeof(CryptoKxTx), (u8 *)dh,
                                     sizeof(CryptoKxTx)))
    return 1;

  if (crypto_kdf_hkdf_sha256_expand((u8 *)rk_out, SIGNAL_DRAT_CHAIN_SZ,
                                    DRAT_KDF_ROOT, sizeof(DRAT_KDF_ROOT) - 1,
                                    key))
    return 1;
  if (crypto_kdf_hkdf_sha256_expand((u8 *)chain_out, SIGNAL_DRAT_CHAIN_SZ,
                                    DRAT_KDF_CHAIN, sizeof(DRAT_KDF_CHAIN) - 1,
                                    key))
    return 1;
  return 0;
}

Signal_Status drat_init(DratState *state, const DratInit *init) {
  *state = (DratState){0};

  // state.DHs = bob_dh_key_pair
  state->key.pk = *init->pk;
  state->key.sk = *init->sk;

  // state.RK = SK
  STATIC_CHECK(sizeof(state->root_key) == sizeof(*init->session_key));
  memcpy(state->root_key, (u8 *)init->session_key, sizeof(state->root_key));

  return 0;
}

Signal_Status drat_init_recv(DratState *state, const DratInitRecv *init) {
  *state = (DratState){0};

  // state.DHs = GENERATE_DH()
  crypto_kx_keypair((u8 *)&state->key.pk, (u8 *)&state->key.sk);
  // state.DHr = bob_dh_public_key
  state->remote_key = *init->bob;

  // state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
  CryptoKxTx dh;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->remote_key, &dh))
    return 1;
  if (drat_kdf_rk((u8 *)init->session_key, &dh, state->root_key,
                  state->chain_send))
    return 1;

  return 0;
}

usize drat_encrypt_len(usize msg_len) { return msg_len; }

static Signal_Status drat_kdf_ck(u8 *ck, u8 *ck_out, CryptoKxTx *mk_out) {
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == SIGNAL_DRAT_CHAIN_SZ);
  if (crypto_kdf_hkdf_sha256_expand(ck_out, SIGNAL_DRAT_CHAIN_SZ, "a", 1, ck))
    return 1;
  if (crypto_kdf_hkdf_sha256_expand((u8 *)mk_out, sizeof(CryptoKxTx), "b", 1,
                                    ck))
    return 1;
  return 0;
}

static Signal_Status drat_hash_ad_header(Bytes ad, const DratHeader *header,
                                         u8 *out) {
  // H(AD) = BLAKE2b(CONCAT(AD, header))
  crypto_generichash_state h;
  if (crypto_generichash_init(&h, 0, 0, 64))
    return 1;
  if (crypto_generichash_update(&h, ad.buf, ad.len))
    return 1;
  if (crypto_generichash_update(&h, (u8 *)header,
                                ((u8 *)&header->tag - (u8 *)header)))
    return 1;
  if (crypto_generichash_final(&h, out, 64))
    return 1;
  return 0;
}

Signal_Status drat_encrypt(DratState *state, Bytes msg, Bytes ad,
                           DratHeader *header, Bytes *cipher) {
  if (cipher->len != drat_encrypt_len(msg.len))
    return 1;

  // state.CKs, mk = KDF_CK(state.CKs)
  CryptoKxTx mk;
  u8 ck[SIGNAL_DRAT_CHAIN_SZ];
  STATIC_CHECK(sizeof(ck) == sizeof(state->chain_send));
  if (drat_kdf_ck(state->chain_send, ck, &mk))
    return 1;
  memcpy(state->chain_send, ck, sizeof(ck));

  // header = HEADER(state.DHs, state.PN, state.Ns)
  header->ratchet = state->key.pk;
  header->chain_len = state->chain_len;
  header->number = state->send_n;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[64];
  drat_hash_ad_header(ad, header, h_ad);

  // state.Ns += 1
  state->send_n++;

  // ENCRYPT(mk, plaintext, H(AD))
  STATIC_CHECK(sizeof(mk) == crypto_aead_chacha20poly1305_KEYBYTES);
  u8 nonce[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
  *(u64 *)nonce = header->number;
  if (crypto_aead_chacha20poly1305_encrypt_detached(
          cipher->buf, (u8 *)&header->tag, 0, msg.buf, msg.len, h_ad,
          sizeof(h_ad), 0, nonce, (u8 *)&mk))
    return 1;

  return 0;
}

static Signal_Status drat_skip(DratState *state, u64 until) {
  // TODO
  CHECK(false, "unimpl skip");
  return 0;
}

static Signal_Status drat_ratchet(DratState *state, const DratHeader *header) {
  // state.PN = state.Ns
  state->chain_len = state->send_n;
  // state.Ns = 0
  state->send_n = 0;
  // state.Nr = 0
  state->recv_n = 0;
  // state.DHr = header.dh
  state->remote_key = header->ratchet;

  // DH1 = DH(state.DHs, state.DHr)
  CryptoKxTx dh1;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->remote_key, &dh1))
    return 1;
  // state.RK, state.CKr = KDF_RK(state.RK, DH1)
  u8 rk[SIGNAL_DRAT_CHAIN_SZ];
  if (drat_kdf_rk(state->root_key, &dh1, rk, state->chain_recv))
    return 1;
  memcpy(state->root_key, rk, sizeof(rk));

  // state.DHs = GENERATE_DH()
  crypto_kx_keypair((u8 *)&state->key.pk, (u8 *)&state->key.sk);
  // DH2 = DH(state.DHs, state.DHr)
  CryptoKxTx dh2;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->remote_key, &dh2))
    return 1;
  // state.RK, state.CKs = KDF_RK(state.RK, DH2)
  if (drat_kdf_rk(state->root_key, &dh2, rk, state->chain_send))
    return 1;
  memcpy(state->root_key, rk, sizeof(rk));

  return 0;
}

Signal_Status drat_decrypt(DratState *state, const DratHeader *header,
                           Bytes cipher, Bytes ad) {
  // TODO: TrySkippedMessageKeys

  // if header.dh != state.DHr
  if (memcmp((u8 *)&header->ratchet, (u8 *)&state->remote_key,
             sizeof(header->ratchet)) != 0) {
    // SkipMessageKeys(state, header.pn)
    if (state->recv_n < header->chain_len)
      if (drat_skip(state, header->chain_len))
        return 1;
    // DHRatchet(state, header)
    if (drat_ratchet(state, header))
      return 1;
  }

  if (state->recv_n < header->number)
    // SkipMessageKeys(state, header.n)
    if (drat_skip(state, header->number))
      return 1;

  // state.CKr, mk = KDF_CK(state.CKr)
  CryptoKxTx mk;
  u8 ck[SIGNAL_DRAT_CHAIN_SZ];
  STATIC_CHECK(sizeof(ck) == sizeof(state->chain_recv));
  if (drat_kdf_ck(state->chain_recv, ck, &mk))
    return 1;
  memcpy(state->chain_recv, ck, sizeof(ck));

  // state.Nr += 1
  state->recv_n++;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[64];
  drat_hash_ad_header(ad, header, h_ad);

  // DECRYPT(mk, ciphertext, H(AD))
  u8 nonce[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
  *(u64 *)nonce = header->number;
  if (crypto_aead_chacha20poly1305_decrypt_detached(
          cipher.buf, 0, cipher.buf, cipher.len, (u8 *)&header->tag, h_ad,
          sizeof(h_ad), nonce, (u8 *)&mk))
    return 1;

  return 0;
}
