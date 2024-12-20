#include "dataenc_parse_share.h"
#include "stdmacros.h"
#include "stdtypes.h"

typedef enum {
  Tokenizer_END = -1,
  Tokenizer_OK,
  Tokenizer_INVALID_NAME,
  Tokenizer_INVALID_STR,
  Tokenizer_INVALID_INT,
  Tokenizer_INVALID_FLOAT,
} TokenizerStatus;

typedef struct {
  Str   cur;
  usize lineno;
  usize lineoffset;
} Tokenizer;

MUST_USE(TokenizerStatus) Tokenizer_next(Tokenizer* t, DataencParseToken* tok);
void DataencParseToken_log(DataencParseToken* tok);
