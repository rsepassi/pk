#include "libbase58.h"

#include "sodium.h"

bool libb58_sha256_impl(void* out, const void* msg, size_t msg_len) {
  crypto_hash_sha256(out, msg, msg_len);
  return true;
}
