#include "keyio.h"
#include "log.h"
#include "unity.h"

// From ssh-keygen -t ed25519

const char* ssh_private =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACBPXWyHaQqQ7sfsFgEPuMoZ354WJbWrnanmUGeFJFnPRQAAAJiG53ymhud8\n"
    "pgAAAAtzc2gtZWQyNTUxOQAAACBPXWyHaQqQ7sfsFgEPuMoZ354WJbWrnanmUGeFJFnPRQ\n"
    "AAAED7BmyX0u9mlBrW7QeI4fJu63lLKrmCI4G3HqAbTQ5IOE9dbIdpCpDux+wWAQ+4yhnf\n"
    "nhYltaudqeZQZ4UkWc9FAAAAE3J5YW5AcnlhbnMtdGhpbmtwYWQBAg==\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

const char* ssh_pub =
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIE9dbIdpCpDux+wWAQ+4yhnfnhYltaudqeZQZ4UkWc9F "
    "foo@bar\n";

void test_keyio(void) {
  Str sk_contents = str_from_c(ssh_private);
  Str pk_contents = str_from_c(ssh_pub);

  CryptoSignSK sk;
  CHECK0(keyio_keydecode_openssh(sk_contents, &sk));

  CryptoSignPK pk;
  CHECK0(keyio_keydecode_openssh_pub(pk_contents, &pk));

  LOGB(CryptoBytes(sk));
  LOGB(CryptoBytes(pk));
  CHECK0(memcmp(&sk.pk, &pk, sizeof(pk)));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  CHECK0(sodium_init());

  UNITY_BEGIN();
  RUN_TEST(test_keyio);
  return UNITY_END();
}
