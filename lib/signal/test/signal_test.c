#include "drat.h"
#include "log.h"
#include "unity.h"
#include "x3dh.h"

static int drat_a_to_b(DratState* A_state, DratState* B_state, Str msg,
                       Str ad) {
  // A sends
  DratHeader header;
  usize      cipher_sz = drat_encrypt_len(msg.len);
  Bytes      cipher    = {cipher_sz, malloc(cipher_sz)};
  if (drat_encrypt(A_state, msg, ad, &header, &cipher))
    return 1;

  // B receives
  if (drat_decrypt(B_state, &header, cipher, ad))
    return 1;

  // decrypt(encrypt(msg)) == msg
  CHECK(str_eq(msg, cipher));
  free(cipher.buf);
  return 0;
}

static void test_drat() {
  // Alice and Bob identity keys
  CryptoSignKeypair A_keys;
  CHECK0(crypto_sign_ed25519_keypair((u8*)&A_keys.pk, (u8*)&A_keys.sk));
  CryptoSignKeypair B_keys;
  CHECK0(crypto_sign_ed25519_keypair((u8*)&B_keys.pk, (u8*)&B_keys.sk));

  X3DHKeys A_sec;
  X3DHKeys B_sec;
  CHECK0(x3dh_keys_init(&A_keys.sk, &A_sec));
  CHECK0(x3dh_keys_init(&B_keys.sk, &B_sec));

  // Alice initiates x3dh and double ratchet
  X3DHHeader A_header;
  X3DH       A_x;
  DratState  A_state;
  {
    DratInit A_init = {
        .session_key = &A_x.key,
        .pk          = &A_sec.pub.shortterm,
        .sk          = &A_sec.sec.shortterm,
    };
    CHECK0(x3dh_init(&A_sec, &B_sec.pub, &A_header, &A_x));
    CHECK0(drat_init(&A_state, &A_init));
  }

  // Bob receives and initiates double ratchet
  X3DH      B_x;
  DratState B_state;
  {
    CHECK0(x3dh_init_recv(&B_sec, &A_header, &B_x));
    DratInitRecv B_init = {
        .session_key = &B_x.key,
        .bob         = &A_sec.pub.shortterm,
    };
    CHECK0(drat_init_recv(&B_state, &B_init));
  }

  CHECK0(sodium_memcmp(&A_x, &B_x, sizeof(A_x)));

  // First message carries the x3dh AD
  CHECK0(drat_a_to_b(&A_state, &B_state,  //
                     Str("first message"), BytesArray(A_x.ad)));
  CHECK0(drat_a_to_b(&A_state, &B_state,  //
                     Str("second message"), BytesZero));

  // Send some messages back and forth
  CHECK0(drat_a_to_b(&B_state, &A_state,  //
                     Str("hello from Bob! secret number is 77"), BytesZero));
  CHECK0(drat_a_to_b(&B_state, &A_state,  //
                     Str("hello from Bob! secret number is 79"), BytesZero));
  CHECK0(drat_a_to_b(&A_state, &B_state,  //
                     Str("hello from Alice!"), BytesZero));
  CHECK0(drat_a_to_b(&B_state, &A_state,  //
                     Str("roger roger"), BytesZero));
  CHECK0(drat_a_to_b(&B_state, &A_state,  //
                     Str("roger roger 2"), BytesZero));
  CHECK0(drat_a_to_b(&A_state, &B_state,  //
                     Str("1"), BytesZero));
  CHECK0(drat_a_to_b(&A_state, &B_state,  //
                     Str("2"), BytesZero));
}

static void test_x3dh() {
  // Alice and Bob each have long-term identity keys
  CryptoSignKeypair A_keys;
  CHECK0(crypto_sign_ed25519_keypair((u8*)&A_keys.pk, (u8*)&A_keys.sk));
  CryptoSignKeypair B_keys;
  CHECK0(crypto_sign_ed25519_keypair((u8*)&B_keys.pk, (u8*)&B_keys.sk));

  // Alice generates and signs a short-term key
  X3DHKeys A_sec;
  CHECK0(x3dh_keys_init(&A_keys.sk, &A_sec));

  // Bob generates and signs a short-term key
  X3DHKeys B_sec;
  CHECK0(x3dh_keys_init(&B_keys.sk, &B_sec));

  // Alice derives key and sends X3DHHeader
  X3DH       A_x;
  X3DHHeader A_header;
  CHECK0(x3dh_init(&A_sec, &B_sec.pub, &A_header, &A_x));

  // Bob receives X3DHHeader and derives key
  X3DH B_x;
  CHECK0(x3dh_init_recv(&B_sec, &A_header, &B_x));

  // Keys + AD are equal
  CHECK0(sodium_memcmp((u8*)&A_x, (u8*)&B_x, sizeof(X3DH)));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  CHECK0(sodium_init());

  UNITY_BEGIN();
  RUN_TEST(test_x3dh);
  RUN_TEST(test_drat);
  return UNITY_END();
}
