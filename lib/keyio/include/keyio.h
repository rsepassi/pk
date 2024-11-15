#pragma once

#include "crypto.h"
#include "stdtypes.h"

int keyio_openssh_parsekey(Str contents, Allocator al, CryptoSignSK* out);
