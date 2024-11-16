#pragma once

#include "crypto.h"
#include "stdtypes.h"

int keyio_getpass(Bytes* pw);
bool keyio_key_is_pwprotected(Str contents);
int keyio_keydecode(Str contents, Str password, CryptoSignSK* out);
int keyio_keyencode(const CryptoSignKeypair* keys, Str password, Allocator al,
                    Str* sk_out, Str* pk_out);
int keyio_keydecode_openssh(Str contents, Allocator al, CryptoSignSK* out);
