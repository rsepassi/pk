#include "nik_hs.h"

#include "log.h"

#define NIK_IDENTIFIER "nik pk v1"
#define NIK_KDF_CTX "pkikkdf1"
#define NIK_HSZ 32

#define NIK_INITIATOR 1
#define NIK_RESPONDER 0

// T1, T2 := KDF_2(C, DH(sk, bob))
// T1 u8[NIK_HSZ]
// T2 u8[NIK_HSZ]
// C  u8[NIK_CHAIN_SZ]
static NIK_Status nik_dh_kdf2(u8* T1, u8* T2, const u8* C, const CryptoKxPK* pk,
                              const CryptoKxSK* sk, const CryptoKxPK* bob,
                              bool initiator) {
  STATIC_CHECK(STRLEN(NIK_KDF_CTX) == crypto_kdf_blake2b_CONTEXTBYTES);
  STATIC_CHECK(NIK_HSZ == crypto_kdf_blake2b_KEYBYTES);

  // DH(E_priv_i, S_pub_r)
  CryptoKxTx dh;
  if (initiator) {
    if (crypto_kx_client_session_keys((u8*)&dh, 0, (u8*)pk, (u8*)sk, (u8*)bob))
      return 1;
  } else {
    if (crypto_kx_server_session_keys((u8*)&dh, 0, (u8*)pk, (u8*)sk, (u8*)bob))
      return 1;
  }

  // Key := Hash(C, DH)
  u8 key[crypto_kdf_blake2b_KEYBYTES];
  if (crypto_generichash_blake2b(key, sizeof(key), C, NIK_CHAIN_SZ, (u8*)&dh,
                                 sizeof(dh)))
    return 1;

  // T1 = KDF(Key, 1)
  if (crypto_kdf_blake2b_derive_from_key(T1, NIK_HSZ, 1, NIK_KDF_CTX, key))
    return 1;

  if (T2) {
    // T2 = KDF(T1, 2)
    if (crypto_kdf_blake2b_derive_from_key(T2, NIK_HSZ, 2, NIK_KDF_CTX, T1))
      return 1;
  }

  return 0;
}

static NIK_Status nikhs_handshake1_check(NIK_HandshakeState* state,
                                         const NIK_Keys keys,
                                         NIK_Handshake1* hs) {
  *state = (NIK_HandshakeState){0};
  state->keys = keys;
  state->initiator = false;

  // Responder static key
  CryptoKxPK* S_pub_r = keys.pk;
  CryptoKxSK* S_priv_r = keys.sk;

  // Initiator static key
  CryptoKxPK* S_pub_i = keys.bob;

  // C_i := Hash(Construction)
  u8* C_i = state->chaining_key;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8*)NIK_CONSTRUCTION,
                                 STRLEN(NIK_CONSTRUCTION), 0, 0))
    return 1;
  // H_i
  crypto_generichash_blake2b_state* H_state = &state->hash;
  if (crypto_generichash_blake2b_init(H_state, 0, 0, NIK_HSZ))
    return 1;
  // C_i := Hash(Construction)
  if (crypto_generichash_blake2b_update(H_state, (u8*)NIK_CONSTRUCTION,
                                        STRLEN(NIK_CONSTRUCTION)))
    return 1;
  // H_i := Hash(C_i || Identifier)
  if (crypto_generichash_blake2b_update(H_state, (u8*)NIK_IDENTIFIER,
                                        STRLEN(NIK_IDENTIFIER)))
    return 1;
  // H_i := Hash(H_i || S_pub_r)
  if (crypto_generichash_blake2b_update(H_state, (u8*)S_pub_r,
                                        sizeof(*S_pub_r)))
    return 1;

  // C_i := KDF_1(C_i, E_pub_i)
  {
    // T0 = Hash(C_i, E_pub_i)
    STATIC_CHECK(crypto_kdf_blake2b_KEYBYTES == NIK_HSZ);
    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ,
                                   (u8*)&hs->ephemeral, sizeof(hs->ephemeral)))
      return 1;

    // T1 = KDF(T0, 1)
    if (crypto_kdf_blake2b_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
  }

  // H_i := Hash(H_i || hs.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->ephemeral,
                                        sizeof(hs->ephemeral)))
    return 1;

  // C_i, k := KDF_2(C_i, DH(S_priv_r, E_pub_i))
  u8 K[NIK_HSZ];
  if (nik_dh_kdf2(C_i, K, C_i, S_pub_r, S_priv_r, &hs->ephemeral,
                  NIK_RESPONDER))
    return 1;

  // hs.static := AEAD(K, 0, S_pub_i, H_i)
  u8 key_decrypt[sizeof(*S_pub_i)];
  {
    // Snapshot H_i
    u8 H[NIK_HSZ];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, S_pub_i, H_i)
    u8 zero_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            key_decrypt, 0, (u8*)&hs->statik, sizeof(hs->statik), (u8*)&hs->tag,
            H, sizeof(H), zero_nonce, K))
      return 1;

    if (sodium_memcmp(key_decrypt, S_pub_i, sizeof(*S_pub_i)))
      return NIK_ErrFailedVerify;
  }

  // H_i := Hash(H_i || hs.static)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->statik,
                                        sizeof(hs->statik) + sizeof(hs->tag)))
    return 1;

  // Copy the decrypted key back into the message
  memcpy((u8*)&hs->statik, key_decrypt, sizeof(key_decrypt));

  // C_i, K := KDF_2(C_i, DH(S_priv_r, S_pub_i))
  if (nik_dh_kdf2(C_i, K, C_i, S_pub_r, S_priv_r, S_pub_i, NIK_RESPONDER))
    return 1;

  return 0;
}

static NIK_Status nikhs_handshake2(NIK_HandshakeState* state,
                                   const NIK_Handshake1* hs1,
                                   NIK_Handshake2* hs2) {
  *hs2 = (NIK_Handshake2){0};

  u8* C_r = state->chaining_key;
  crypto_generichash_blake2b_state* H_state = &state->hash;

  // (E_priv_r, E_pub_r) := DH-Generate()
  // hs.ephemeral := E_pub_r
  CryptoKxSK* E_priv_r = &state->ephemeral_sk;
  CryptoKxPK* E_pub_r = &state->ephemeral_pk;
  if (crypto_kx_keypair((u8*)E_pub_r, (u8*)E_priv_r))
    return 1;
  memcpy(&hs2->ephemeral, E_pub_r, sizeof(*E_pub_r));

  // C_r := KDF_1(C_r, E_pub_r)
  {
    // T0 = Hash(C_r, E_pub_r)
    STATIC_CHECK(crypto_kdf_blake2b_KEYBYTES == NIK_HSZ);
    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_r, NIK_CHAIN_SZ,
                                   (u8*)E_pub_r, sizeof(*E_pub_r)))
      return 1;
    // T1 = KDF(T0, 1)
    if (crypto_kdf_blake2b_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
  }

  // H_r := Hash(H_r || hs.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs2->ephemeral,
                                        sizeof(hs2->ephemeral)))
    return 1;

  // C_r := KDF1(C_r, DH(E_priv_r, E_pub_i))
  if (nik_dh_kdf2(C_r, 0, C_r, E_pub_r, E_priv_r, &hs1->ephemeral,
                  NIK_RESPONDER))
    return 1;
  // C_r := KDF1(C_r, DH(E_priv_r, S_pub_i))
  if (nik_dh_kdf2(C_r, 0, C_r, E_pub_r, E_priv_r, state->keys.bob,
                  NIK_RESPONDER))
    return 1;

  // (C_r, T, K) := KDF3(C_r, Q);
  u8 T[NIK_HSZ] = {0};
  u8 K[NIK_HSZ] = {0};
  {
    u8 Q0[sizeof(*state->keys.psk)] = {0};
    u8* Q = Q0;
    if (state->keys.psk)
      Q = (u8*)state->keys.psk;

    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_r, NIK_CHAIN_SZ, Q,
                                   sizeof(Q0)))
      return 1;

    if (crypto_kdf_blake2b_derive_from_key(C_r, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
    if (crypto_kdf_blake2b_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX,
                                           C_r))
      return 1;
    if (crypto_kdf_blake2b_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T))
      return 1;
  }

  // H_r := Hash(H_r || T)
  if (crypto_generichash_blake2b_update(H_state, (u8*)T, sizeof(T)))
    return 1;

  // hs.tag := AEAD(K, 0, e, H_r)
  {
    // Snapshot H_r
    u8 H[NIK_HSZ];
    crypto_generichash_blake2b_state H_r = *H_state;
    if (crypto_generichash_blake2b_final(&H_r, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, e, H_r)
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    STATIC_CHECK(sizeof(hs2->tag) == crypto_aead_chacha20poly1305_IETF_ABYTES);
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            (void*)1, (u8*)&hs2->tag, 0, 0, 0, H, sizeof(H), 0, zero_nonce, K))
      return 1;
  }

  // H_r := Hash(H_r || hs.tag)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs2->tag,
                                        sizeof(hs2->tag)))
    return 1;

  return 0;
}

static NIK_Status nikhs_handshake2_check(NIK_HandshakeState* state,
                                         const NIK_Handshake2* hs) {
  // No changes are made to the state unless the message checks out
  u8 C_copy[NIK_CHAIN_SZ];
  memcpy(C_copy, state->chaining_key, NIK_CHAIN_SZ);
  crypto_generichash_blake2b_state H_copy = state->hash;

  u8* C_i = C_copy;
  crypto_generichash_blake2b_state* H_state = &H_copy;

  // C_i := KDF_1(C_i, E_pub_r)
  {
    // T0 = Hash(C_i, E_pub_r)
    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ,
                                   (u8*)&hs->ephemeral, sizeof(hs->ephemeral)))
      return 1;
    // T1 = KDF(T0, 1)
    if (crypto_kdf_blake2b_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
  }

  // H_r := Hash(H_r || hs.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->ephemeral,
                                        sizeof(hs->ephemeral)))
    return 1;

  // C_i := KDF1(C_i, DH(E_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, 0, C_i, &state->ephemeral_pk, &state->ephemeral_sk,
                  &hs->ephemeral, NIK_INITIATOR))
    return 1;
  // C_i := KDF1(C_i, DH(S_priv_i, E_pub_r))
  if (nik_dh_kdf2(C_i, 0, C_i, state->keys.pk, state->keys.sk, &hs->ephemeral,
                  NIK_INITIATOR))
    return 1;

  // (C_i, T, K) := KDF3(C_i, Q);
  u8 T[NIK_HSZ] = {0};
  u8 K[NIK_HSZ] = {0};
  {
    STATIC_CHECK(crypto_secretbox_KEYBYTES == NIK_HSZ);
    u8 Q0[crypto_secretbox_KEYBYTES] = {0};
    u8* Q = Q0;
    if (state->keys.psk)
      Q = (u8*)state->keys.psk;

    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ, Q,
                                   crypto_secretbox_KEYBYTES))
      return 1;

    if (crypto_kdf_blake2b_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
    if (crypto_kdf_blake2b_derive_from_key(T, NIK_CHAIN_SZ, 2, NIK_KDF_CTX,
                                           C_i))
      return 1;
    if (crypto_kdf_blake2b_derive_from_key(K, NIK_CHAIN_SZ, 3, NIK_KDF_CTX, T))
      return 1;
  }

  // H_i := Hash(H_i || T)
  if (crypto_generichash_blake2b_update(H_state, (u8*)T, sizeof(T)))
    return 1;

  // hs.tag := AEAD(K, 0, e, H_i)
  {
    // Snapshot H_i
    u8 H[NIK_HSZ];
    crypto_generichash_blake2b_state H_i = *H_state;
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, e, H_i)
    u8 zero_nonce[crypto_box_NONCEBYTES] = {0};
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            0, 0, (void*)1, 0, (u8*)&hs->tag, H, sizeof(H), zero_nonce, K))
      return NIK_ErrFailedVerify;
  }

  // H_r := Hash(H_r || hs.tag)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->tag,
                                        sizeof(hs->tag)))
    return 1;

  // Apply the state changes
  memcpy(state->chaining_key, C_copy, NIK_CHAIN_SZ);
  state->hash = H_copy;

  return 0;
}

static NIK_Status nikhs_handshake_done(NIK_HandshakeState* state,
                                       NIK_SharedSecret* secret) {
  if (crypto_generichash_blake2b((u8*)&secret->secret, sizeof(secret->secret),
                                 state->chaining_key,
                                 sizeof(state->chaining_key), 0, 0))
    return 1;

  sodium_memzero(state, sizeof(NIK_HandshakeState));

  return 0;
}

NIK_Status nikhs_handshake_start(NIK_HandshakeState* state, const NIK_Keys keys,
                                 NIK_Handshake1* hs) {
  *state = (NIK_HandshakeState){0};
  *hs = (NIK_Handshake1){0};

  state->keys = keys;
  state->initiator = true;

  // Initiator static key
  CryptoKxPK* S_pub_i = keys.pk;
  CryptoKxSK* S_priv_i = keys.sk;

  // Responder static key
  CryptoKxPK* S_pub_r = keys.bob;

  // C_i := Hash(Construction)
  u8* C_i = state->chaining_key;
  if (crypto_generichash_blake2b(C_i, NIK_CHAIN_SZ, (u8*)NIK_CONSTRUCTION,
                                 STRLEN(NIK_CONSTRUCTION), 0, 0))
    return 1;

  // H_i
  crypto_generichash_blake2b_state* H_state = &state->hash;
  if (crypto_generichash_blake2b_init(H_state, 0, 0, NIK_HSZ))
    return 1;
  // C_i := Hash(Construction)
  if (crypto_generichash_blake2b_update(H_state, (u8*)NIK_CONSTRUCTION,
                                        STRLEN(NIK_CONSTRUCTION)))
    return 1;
  // H_i := Hash(C_i || Identifier)
  if (crypto_generichash_blake2b_update(H_state, (u8*)NIK_IDENTIFIER,
                                        STRLEN(NIK_IDENTIFIER)))
    return 1;
  // H_i := Hash(H_i || S_pub_r)
  if (crypto_generichash_blake2b_update(H_state, (u8*)S_pub_r,
                                        sizeof(*S_pub_r)))
    return 1;

  // (E_priv_i, E_pub_i) := DH-Generate()
  // hs.ephemeral := E_pub_i
  CryptoKxSK* E_priv_i = &state->ephemeral_sk;
  CryptoKxPK* E_pub_i = &state->ephemeral_pk;
  if (crypto_kx_keypair((u8*)E_pub_i, (u8*)E_priv_i))
    return 1;
  memcpy(&hs->ephemeral, E_pub_i, sizeof(*E_pub_i));

  // C_i := KDF_1(C_i, E_pub_i)
  {
    // T0 = Hash(C_i, E_pub_i)
    u8 T0[crypto_kdf_blake2b_KEYBYTES];
    if (crypto_generichash_blake2b(T0, sizeof(T0), C_i, NIK_CHAIN_SZ,
                                   (u8*)E_pub_i, sizeof(*E_pub_i)))
      return 1;

    // C_i = T1 = KDF(T0, 1)
    if (crypto_kdf_blake2b_derive_from_key(C_i, NIK_CHAIN_SZ, 1, NIK_KDF_CTX,
                                           T0))
      return 1;
  }

  // H_i := Hash(H_i || hs.ephemeral)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->ephemeral,
                                        sizeof(hs->ephemeral)))
    return 1;

  // C_i, k := KDF_2(C_i, DH(E_priv_i, S_pub_r))
  u8 K[NIK_HSZ];
  if (nik_dh_kdf2(C_i, K, C_i, E_pub_i, E_priv_i, S_pub_r, NIK_INITIATOR))
    return 1;

  // hs.static := AEAD(K, 0, S_pub_i, H_i)
  {
    // Snapshot H_i
    u8 H[NIK_HSZ];
    crypto_generichash_blake2b_state H_i;
    memcpy(&H_i, H_state, sizeof(crypto_generichash_blake2b_state));
    if (crypto_generichash_blake2b_final(&H_i, H, sizeof(H)))
      return 1;

    // AEAD(K, 0, S_pub_i, H_i)
    u8 zero_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            (u8*)&hs->statik, (u8*)&hs->tag, 0, (u8*)S_pub_i, sizeof(*S_pub_i),
            H, sizeof(H), 0, zero_nonce, K))
      return 1;
  }

  // H_i := Hash(H_i || hs.static)
  if (crypto_generichash_blake2b_update(H_state, (u8*)&hs->statik,
                                        sizeof(hs->statik) + sizeof(hs->tag)))
    return 1;

  // C_i, K := KDF_2(C_i, DH(S_priv_i, S_pub_r))
  if (nik_dh_kdf2(C_i, K, C_i, S_pub_i, S_priv_i, S_pub_r, NIK_INITIATOR))
    return 1;

  return 0;
}

NIK_Status nikhs_handshake_responder_finish(NIK_HandshakeState* state,
                                            const NIK_Keys keys,
                                            NIK_Handshake1* hs1,
                                            NIK_Handshake2* hs2,
                                            NIK_SharedSecret* secret) {
  int rc = 0;
  if ((rc = nikhs_handshake1_check(state, keys, hs1)))
    return rc;
  if ((rc = nikhs_handshake2(state, hs1, hs2)))
    return rc;
  if ((rc = nikhs_handshake_done(state, secret)))
    return rc;
  return 0;
}

NIK_Status nikhs_handshake_finish(NIK_HandshakeState* state,
                                  const NIK_Handshake2* hs,
                                  NIK_SharedSecret* secret) {
  int rc = 0;
  if ((rc = nikhs_handshake2_check(state, hs)))
    return rc;
  if ((rc = nikhs_handshake_done(state, secret)))
    return rc;
  return 0;
}
