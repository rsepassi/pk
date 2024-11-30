#include "log.h"
#include "nik_hs.h"
#include "unity.h"

void test_nik(void) {
  // Alice and Bob have x25519 keypairs
  CryptoKxKeypair alice;
  CHECK0(crypto_kx_keypair((u8*)&alice.pk, (u8*)&alice.sk));
  CryptoKxKeypair bob;
  CHECK0(crypto_kx_keypair((u8*)&bob.pk, (u8*)&bob.sk));

  // Alice initiates a handshake
  NIK_HandshakeState alice_state;
  NIK_Handshake1 hs1;
  {
    NIK_Keys alice_keys = {
        .pk = &alice.pk,
        .sk = &alice.sk,
        .bob = &bob.pk,
        .psk = 0,
    };
    CHECK0(nik_handshake_start(&alice_state, alice_keys, &hs1));
  }

  // Bob completes the handshake and responds
  NIK_HandshakeState bob_state;
  NIK_SharedSecret bob_secret;
  NIK_Handshake2 hs2;
  {
    NIK_Keys bob_keys = {
        .pk = &bob.pk,
        .sk = &bob.sk,
        .bob = &alice.pk,
        .psk = 0,
    };
    // Bob checks, responds, and completes the handshake
    CHECK0(nik_handshake_responder_finish(&bob_state, bob_keys, &hs1, &hs2,
                                          &bob_secret));
  }

  // Verify that Charlie's bogus response is rejected and doesn't affect
  // Alice's state
  {
    NIK_Handshake2 bogus = {0};
    CryptoKxSK sk;
    CHECK0(crypto_box_keypair((u8*)&bogus.ephemeral, (u8*)&sk));
    randombytes_buf((u8*)&bogus.tag, sizeof(bogus.tag));
    NIK_SharedSecret s;
    CHECK(nik_handshake_finish(&alice_state, &bogus, &s) ==
          NIK_ErrFailedVerify);
  }

  // Alice completes the handshake
  NIK_SharedSecret alice_secret;
  CHECK0(nik_handshake_finish(&alice_state, &hs2, &alice_secret));

  // Alice and Bob have a shared secret
  CHECK0(sodium_memcmp((u8*)&alice_secret.secret, (u8*)&bob_secret.secret,
                       sizeof(alice_secret.secret)));
}

void setUp(void) { CHECK0(sodium_init()); }

void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_nik);
  return UNITY_END();
}
