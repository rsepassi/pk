#pragma once

#include "stdtypes.h"

typedef int Base64_Status;
#define Base64_OK 0

usize base64_encoded_maxlen(usize in_len);
usize base64_decoded_maxlen(usize in_len);
Base64_Status base64_encode(Bytes in, Bytes* out);
Base64_Status base64_decode(Bytes in, Bytes* out);
