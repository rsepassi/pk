#include "signal.h"

#include "log.h"
#include "fastrange.h"

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
  if (crypto_sign_ed25519_detached((u8 *)&keys->pub.kx_prekey_sig,
                                   0, // signature
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
  if (crypto_sign_ed25519_verify_detached(
          (u8 *)&B->kx_prekey_sig, (u8 *)&B->kx_prekey, sizeof(CryptoKxPK),
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
  for (usize i = 0; i < SIGNAL_DRAT_SKIPMAP_SZ; ++i)
    state->skips.arr[i].key.number = UINT64_MAX;
  randombytes_buf(state->skips.key, sizeof(state->skips.key));

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
  for (usize i = 0; i < SIGNAL_DRAT_SKIPMAP_SZ; ++i)
    state->skips.arr[i].key.number = UINT64_MAX;
  randombytes_buf(state->skips.key, sizeof(state->skips.key));

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
  crypto_generichash_blake2b_state h;
  if (crypto_generichash_blake2b_init(&h, 0, 0, 64))
    return 1;
  if (crypto_generichash_blake2b_update(&h, ad.buf, ad.len))
    return 1;
  if (crypto_generichash_blake2b_update(&h, (u8 *)header,
                                        ((u8 *)&header->tag - (u8 *)header)))
    return 1;
  if (crypto_generichash_blake2b_final(&h, out, 64))
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
  header->psend_n = state->psend_n;
  header->number = state->send_n;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[64];
  drat_hash_ad_header(ad, header, h_ad);

  // state.Ns += 1
  state->send_n++;

  // ENCRYPT(mk, plaintext, H(AD))
  STATIC_CHECK(sizeof(mk) == crypto_aead_chacha20poly1305_IETF_KEYBYTES);
  u8 nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  *(u64 *)nonce = header->number;
  if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
          cipher->buf, (u8 *)&header->tag, 0, msg.buf, msg.len, h_ad,
          sizeof(h_ad), 0, nonce, (u8 *)&mk))
    return 1;

  return 0;
}

static Signal_Status drat_skipped_hash_key(DratState *state,
                                           const CryptoKxPK *pk, u64 number,
                                           u64 *i) {
  DratSkipKey key = {.pk = *pk, .number = number};
  STATIC_CHECK(crypto_shorthash_siphash24_BYTES == 8);
  u64 h;
  if (crypto_shorthash_siphash24((u8 *)&h, (u8 *)&key, sizeof(DratSkipKey),
                                 state->skips.key))
    return 1;
  *i = fastrange64(h, SIGNAL_DRAT_SKIPMAP_SZ);
  return 0;
}

static void drat_skips_cleanup(DratState* state) {
  // TODO
  CHECK(false, "double ratchet skips overflow, unimplemented cleanup");
}

static Signal_Status drat_insert_skipped_mk(DratState *state, CryptoKxPK *pk,
                                            u64 number, DratSkipEntry **entry) {
  if (state->skips.n > SIGNAL_DRAT_MAX_SKIP) {
    drat_skips_cleanup(state);
  }
  u64 i;
  if (drat_skipped_hash_key(state, pk, number, &i))
    return 1;
  while (state->skips.arr[i].key.number != UINT64_MAX)
    ++i;
  *entry = &state->skips.arr[i];
  (*entry)->key.number = number;
  (*entry)->key.pk = *pk;
  state->skips.n++;
  return 0;
}

static Signal_Status drat_skip(DratState *state, u64 until) {
  if ((state->recv_n + SIGNAL_DRAT_MAX_SKIP) < until)
    return 1;
  if (!state->chain_recv_exists)
    return 0;

  while (state->recv_n < until) {
    // state.MKSKIPPED[state.DHr, state.Nr] = mk (computed below)
    DratSkipEntry *entry;
    if (drat_insert_skipped_mk(state, &state->remote_key, state->recv_n,
                               &entry))
      return 1;

    // state.CKr, mk = KDF_CK(state.CKr)
    u8 ck[SIGNAL_DRAT_CHAIN_SZ];
    if (drat_kdf_ck(state->chain_recv, ck, &entry->mk)) {
      entry->key.number = UINT64_MAX;
      state->skips.n--;
      return 1;
    }
    memcpy(state->chain_recv, ck, sizeof(ck));

    // state.Nr += 1
    state->recv_n++;
  }

  return 0;
}

static Signal_Status drat_ratchet(DratState *state, const DratHeader *header) {
  // state.PN = state.Ns
  state->psend_n = state->send_n;
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
  state->chain_recv_exists = true;

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

static Signal_Status drat_find_skipped_mk(DratState *state,
                                          const DratHeader *header,
                                          DratSkipEntry **entry) {
  u64 i;
  if (drat_skipped_hash_key(state, &header->ratchet, header->number, &i))
    return 1;

  *entry = NULL;
  while (state->skips.arr[i].key.number != UINT64_MAX) {
    if (state->skips.arr[i].key.number == header->number &&
        memcmp(&state->skips.arr[i].key.pk, &header->ratchet,
               sizeof(header->ratchet)) == 0) {
      *entry = &state->skips.arr[i];
      return 0;
    }
    i++;
    if (i >= SIGNAL_DRAT_SKIPMAP_SZ) i = 0;
  }
  return 0;
}

static Signal_Status drat_check_skipped(DratState *state,
                                        const DratHeader *header, Bytes cipher,
                                        Bytes ad, bool *found) {
  DratSkipEntry *skip;
  if (drat_find_skipped_mk(state, header, &skip))
    return 1;
  *found = skip != NULL;
  if (skip == NULL)
    return 0;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[64];
  drat_hash_ad_header(ad, header, h_ad);
  // DECRYPT(mk, ciphertext, H(AD))
  u8 nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  *(u64 *)nonce = header->number;
  if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
          cipher.buf, 0, cipher.buf, cipher.len, (u8 *)&header->tag, h_ad,
          sizeof(h_ad), nonce, (u8 *)&skip->mk))
    return 1;

  sodium_memzero(skip, sizeof(DratSkipEntry));
  skip->key.number = UINT64_MAX;
  state->skips.n--;

  return 0;
}

Signal_Status drat_decrypt(DratState *state, const DratHeader *header,
                           Bytes cipher, Bytes ad) {
  // Determine if we need to check the skip list
  // If the keys don't match, we need to check the skip list.
  // If the keys do match, we need to check the skip list if recv_n > number.
  bool key_match = memcmp((u8 *)&header->ratchet, (u8 *)&state->remote_key,
                          sizeof(header->ratchet)) == 0;
  bool check_skips = !key_match || state->recv_n > header->number;
  if (check_skips) {
    bool found;
    if (drat_check_skipped(state, header, cipher, ad, &found))
      return 1;
    if (found)
      return 0;
  }

  // if header.dh != state.DHr
  if (!key_match) {
    // SkipMessageKeys(state, header.pn)
    if (state->recv_n < header->psend_n)
      if (drat_skip(state, header->psend_n))
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
  state->chain_recv_exists = true;

  // state.Nr += 1
  state->recv_n++;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[64];
  drat_hash_ad_header(ad, header, h_ad);

  // DECRYPT(mk, ciphertext, H(AD))
  u8 nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  *(u64 *)nonce = header->number;
  if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
          cipher.buf, 0, cipher.buf, cipher.len, (u8 *)&header->tag, h_ad,
          sizeof(h_ad), nonce, (u8 *)&mk))
    return 1;

  return 0;
}
