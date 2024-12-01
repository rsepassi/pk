#include "drat.h"
#include "log.h"
#include "unity.h"
#include "x3dh.h"

static int drat_a_to_b(DratState* A_state, X3DH* A_x, DratState* B_state,
                       X3DH* B_x, Str msg) {
  // A sends
  Bytes A_ad = BytesArray(A_x->ad);
  DratHeader header;
  usize cipher_sz = drat_encrypt_len(msg.len);
  Bytes cipher = {cipher_sz, malloc(cipher_sz)};
  if (drat_encrypt(A_state, msg, A_ad, &header, &cipher))
    return 1;

  // B receives
  Bytes B_ad = BytesArray(B_x->ad);
  if (drat_decrypt(B_state, &header, cipher, B_ad))
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

  // X3DH
  X3DHKeys A_sec;
  X3DHKeys B_sec;
  X3DH A_x;
  X3DH B_x;
  {
    CHECK0(x3dh_keys_init(&A_keys.sk, &A_sec));
    CHECK0(x3dh_keys_init(&B_keys.sk, &B_sec));
    X3DHHeader A_header;
    CHECK0(x3dh_init(&A_sec, &B_sec.pub, &A_header, &A_x));
    CHECK0(x3dh_init_recv(&B_sec, &A_header, &B_x));
    CHECK0(sodium_memcmp((u8*)&A_x, (u8*)&B_x, sizeof(X3DH)));
  }

  // Initialize double ratchet
  DratState B_state;
  DratInit B_init = {
      .session_key = &B_x.key,
      .pk = &B_sec.pub.shortterm,
      .sk = &B_sec.sec.shortterm,
  };
  CHECK0(drat_init(&B_state, &B_init));

  DratState A_state;
  DratInitRecv A_init = {
      .session_key = &A_x.key,
      .bob = &B_sec.pub.shortterm,
  };
  CHECK0(drat_init_recv(&A_state, &A_init));

  // Send some messages back and forth
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x,  //
                     Str("hello from Bob! secret number is 77")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x,  //
                     Str("hello from Bob! secret number is 79")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x,  //
                     Str("hello from Alice!")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x,  //
                     Str("roger roger")));
  CHECK0(drat_a_to_b(&B_state, &B_x, &A_state, &A_x,  //
                     Str("roger roger 2")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x,  //
                     Str("1")));
  CHECK0(drat_a_to_b(&A_state, &A_x, &B_state, &B_x,  //
                     Str("2")));
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

  // Alice sends X3DHHeader and derives key
  X3DH A_x;
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
