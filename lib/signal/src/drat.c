#include "drat.h"

#include "fastrange.h"
#include "log.h"
#include "stdmacros.h"

#define DRAT_KDF_ROOT  "drat-kdf-root"
#define DRAT_KDF_CHAIN "drat-kdf-chain"
#define DRAT_AD_HSZ    32

static Drat_Status drat_dh(CryptoKxPK* pk, CryptoKxSK* sk, CryptoKxPK* bob,
                           CryptoKxTx* dh) {
  // memcmp OK: public key
  bool isclient = memcmp(pk, bob, sizeof(CryptoKxPK)) < 0;
  if (isclient) {
    if (crypto_kx_client_session_keys(0, (u8*)dh, (u8*)pk, (u8*)sk, (u8*)bob))
      return 1;
  } else {
    if (crypto_kx_server_session_keys(0, (u8*)dh, (u8*)pk, (u8*)sk, (u8*)bob))
      return 1;
  }
  return 0;
}

static Drat_Status drat_kdf_rk(u8* rk, CryptoKxTx* dh, u8* rk_out,
                               u8* chain_out) {
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == sizeof(CryptoKxTx));
  u8 key[crypto_kdf_hkdf_sha256_KEYBYTES];
  if (crypto_kdf_hkdf_sha256_extract(key, rk, sizeof(CryptoKxTx), (u8*)dh,
                                     sizeof(CryptoKxTx)))
    return 1;

  if (crypto_kdf_hkdf_sha256_expand((u8*)rk_out, DRAT_CHAIN_SZ, DRAT_KDF_ROOT,
                                    STRLEN(DRAT_KDF_ROOT), key))
    return 1;
  if (crypto_kdf_hkdf_sha256_expand((u8*)chain_out, DRAT_CHAIN_SZ,
                                    DRAT_KDF_CHAIN, STRLEN(DRAT_KDF_CHAIN),
                                    key))
    return 1;
  return 0;
}

Drat_Status drat_init(DratState* state, const DratInit* init) {
  *state = (DratState){0};

  // state.DHs = bob_dh_key_pair
  state->key.pk = *init->pk;
  state->key.sk = *init->sk;

  // state.RK = SK
  STATIC_CHECK(sizeof(state->root_key) == sizeof(*init->session_key));
  memcpy(state->root_key, (u8*)init->session_key, sizeof(state->root_key));

  return 0;
}

Drat_Status drat_init_recv(DratState* state, const DratInitRecv* init) {
  *state = (DratState){0};

  // state.DHs = GENERATE_DH()
  crypto_kx_keypair((u8*)&state->key.pk, (u8*)&state->key.sk);
  // state.DHr = bob_dh_public_key
  state->bob = *init->bob;

  // state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
  CryptoKxTx dh;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->bob, &dh))
    return 1;
  if (drat_kdf_rk((u8*)init->session_key, &dh, state->root_key,
                  state->chain_send))
    return 1;

  sodium_memzero(&dh, sizeof(dh));

  return 0;
}

usize drat_encrypt_len(usize msg_len) { return msg_len; }

static Drat_Status drat_kdf_ck(const u8* ck, u8* ck_out, CryptoKxTx* mk_out) {
  STATIC_CHECK(crypto_kdf_hkdf_sha256_KEYBYTES == DRAT_CHAIN_SZ);
  if (crypto_kdf_hkdf_sha256_expand(ck_out, DRAT_CHAIN_SZ, "a", 1, ck))
    return 1;
  if (crypto_kdf_hkdf_sha256_expand((u8*)mk_out, sizeof(CryptoKxTx), "b", 1,
                                    ck))
    return 1;
  return 0;
}

static Drat_Status drat_hash_ad_header(Bytes ad, const DratHeader* header,
                                       u8* out) {
  // H(AD) = BLAKE2b(CONCAT(AD, header))
  crypto_generichash_blake2b_state h;
  if (crypto_generichash_blake2b_init(&h, 0, 0, DRAT_AD_HSZ))
    return 1;
  if (crypto_generichash_blake2b_update(&h, ad.buf, ad.len))
    return 1;
  if (crypto_generichash_blake2b_update(&h, (u8*)header,
                                        ((u8*)&header->tag - (u8*)header)))
    return 1;
  if (crypto_generichash_blake2b_final(&h, out, DRAT_AD_HSZ))
    return 1;
  return 0;
}

Drat_Status drat_encrypt(DratState* state, Bytes msg, Bytes ad,
                         DratHeader* header, Bytes* cipher) {
  if (cipher->len != drat_encrypt_len(msg.len))
    return 1;

  // state.CKs, mk = KDF_CK(state.CKs)
  CryptoKxTx mk;
  u8         ck[DRAT_CHAIN_SZ];
  STATIC_CHECK(sizeof(ck) == sizeof(state->chain_send));
  if (drat_kdf_ck(state->chain_send, ck, &mk))
    return 1;
  memcpy(state->chain_send, ck, sizeof(ck));

  // header = HEADER(state.DHs, state.PN, state.Ns)
  header->key     = state->key.pk;
  header->psend_n = state->psend_n;
  header->send_n  = state->send_n;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[DRAT_AD_HSZ];
  if (drat_hash_ad_header(ad, header, h_ad))
    return 1;

  // state.Ns += 1
  state->send_n++;

  // ENCRYPT(mk, plaintext, H(AD))
  STATIC_CHECK(sizeof(mk) == crypto_aead_chacha20poly1305_IETF_KEYBYTES);
  u8 nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  *(u64*)nonce                                          = header->send_n;
  if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
          cipher->buf, (u8*)&header->tag, 0, msg.buf, msg.len, h_ad,
          sizeof(h_ad), 0, nonce, (u8*)&mk))
    return 1;

  sodium_memzero(&mk, sizeof(mk));
  sodium_memzero(ck, sizeof(ck));

  return 0;
}

static Drat_Status drat_ratchet(DratState* state, const DratHeader* header) {
  // state.PN = state.Ns
  state->psend_n = state->send_n;
  // state.Ns = 0
  state->send_n = 0;
  // state.Nr = 0
  state->recv_n = 0;
  // state.DHr = header.dh
  state->bob = header->key;

  // DH1 = DH(state.DHs, state.DHr)
  CryptoKxTx dh1;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->bob, &dh1))
    return 1;
  // state.RK, state.CKr = KDF_RK(state.RK, DH1)
  u8 rk[DRAT_CHAIN_SZ];
  if (drat_kdf_rk(state->root_key, &dh1, rk, state->chain_recv))
    return 1;
  memcpy(state->root_key, rk, sizeof(rk));

  // state.DHs = GENERATE_DH()
  crypto_kx_keypair((u8*)&state->key.pk, (u8*)&state->key.sk);
  // DH2 = DH(state.DHs, state.DHr)
  CryptoKxTx dh2;
  if (drat_dh(&state->key.pk, &state->key.sk, &state->bob, &dh2))
    return 1;
  // state.RK, state.CKs = KDF_RK(state.RK, DH2)
  if (drat_kdf_rk(state->root_key, &dh2, rk, state->chain_send))
    return 1;
  memcpy(state->root_key, rk, sizeof(rk));

  sodium_memzero(&dh1, sizeof(dh1));
  sodium_memzero(&dh2, sizeof(dh2));
  sodium_memzero(rk, sizeof(rk));

  return 0;
}

Drat_Status drat_decrypt(DratState* ostate, const DratHeader* header,
                         Bytes cipher, Bytes ad) {
  // To prevent updating state before actually authenticating the message,
  // we apply all updates to a copy of the session state, and only after
  // authentication do we apply it to the actual state.
  STATIC_CHECK(sizeof(DratState) < 512);  // to ensure we limit the size
  DratState  state_copy = *ostate;
  DratState* state      = &state_copy;

  // Has the peer changed keys?
  // memcmp OK: public key
  bool key_match =
      memcmp((u8*)&header->key, (u8*)&state->bob, sizeof(header->key)) == 0;

  // if header.dh != state.DHr
  if (!key_match) {
    if (state->recv_n > header->psend_n)
      return 1;
    // DHRatchet(state, header)
    if (drat_ratchet(state, header))
      return 1;
  }

  if (state->recv_n > header->send_n)
    return 1;

  // state.CKr, mk = KDF_CK(state.CKr)
  CryptoKxTx mk;
  u8         ck[DRAT_CHAIN_SZ];
  STATIC_CHECK(sizeof(ck) == sizeof(state->chain_recv));
  if (drat_kdf_ck(state->chain_recv, ck, &mk))
    return 1;
  memcpy(state->chain_recv, ck, sizeof(ck));

  // state.Nr += 1
  state->recv_n++;

  // H(AD) = BLAKE2b(CONCAT(AD, header))
  u8 h_ad[DRAT_AD_HSZ];
  if (drat_hash_ad_header(ad, header, h_ad))
    return 1;

  // DECRYPT(mk, ciphertext, H(AD))
  u8 nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  *(u64*)nonce                                          = header->send_n;
  if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
          cipher.buf, 0, cipher.buf, cipher.len, (u8*)&header->tag, h_ad,
          sizeof(h_ad), nonce, (u8*)&mk))
    return 1;

  // Update the state only after successful authentication
  *ostate = *state;

  sodium_memzero(ck, sizeof(ck));
  sodium_memzero(&mk, sizeof(mk));
  sodium_memzero(state, sizeof(DratState));

  return 0;
}
