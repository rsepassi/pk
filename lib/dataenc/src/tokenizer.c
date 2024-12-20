#include "tokenizer.h"

#include "dataenc_parse_tokens.h"

typedef struct {
  char* word;
  int   len;
  int   token;
} TokenizerReserved;

TokenizerReserved reserved_words[] = {
    {"i8", 2, Token_I8},
    {"u8", 2, Token_U8},
    {"let", 3, Token_LET},
    {"i16", 3, Token_I16},
    {"i32", 3, Token_I32},
    {"i64", 3, Token_I64},
    {"u16", 3, Token_U16},
    {"u64", 3, Token_U64},
    {"f32", 3, Token_F32},
    {"f64", 3, Token_F64},
    {"bool", 4, Token_BOOL},
    {"enum", 4, Token_ENUM},
    {"null", 4, Token_LITERAL_NULL},
    {"true", 4, Token_LITERAL_TRUE},
    {"void", 4, Token_VOID},
    {"union", 5, Token_UNION},
    {"false", 5, Token_LITERAL_FALSE},
    {"struct", 6, Token_STRUCT},
    {"bitset", 6, Token_BITSET},
    {"import", 6, Token_IMPORT},
    {"include", 7, Token_INCLUDE},
};

static int Tokenizer_punct(u8 c) {
  int token = 0;
  switch (c) {
    case ';':
      token = Token_SEMICOLON;
      break;
    case '=':
      token = Token_EQ;
      break;
    case '{':
      token = Token_LBRACE;
      break;
    case '}':
      token = Token_RBRACE;
      break;
    case '(':
      token = Token_LPAREN;
      break;
    case ')':
      token = Token_RPAREN;
      break;
    case '[':
      token = Token_LBRACK;
      break;
    case ']':
      token = Token_RBRACK;
      break;
    case '?':
      token = Token_QUESTION;
      break;
    case ',':
      token = Token_COMMA;
      break;
    case '.':
      token = Token_DOT;
      break;
    case ':':
      token = Token_COLON;
      break;
    default:
      break;
  }
  return token;
}

static inline bool Tokenizer_is_whitespace(u8 c) {
  return c == ' ' || c == '\t' || c == '\n';
}

static inline u8 Tokenizer_advance_char(Tokenizer* t) {
  CHECK(t->cur.len);
  Str out = bytes_advance(&t->cur, 1);
  t->lineoffset++;
  return out.buf[0];
}

static inline u8 Tokenizer_peek_char(Tokenizer* t) {
  CHECK(t->cur.len);
  return t->cur.buf[0];
}

static inline void Tokenizer_advance_line(Tokenizer* t) {
  Tokenizer_advance_char(t);
  t->lineno++;
  t->lineoffset = 0;
}

static bool Tokenizer_valid_name(Str s) {
  // A name is alpha-numeric + underscores
  for (usize i = 0; i < s.len; ++i) {
    u8 c = s.buf[i];
    if (c == '_')
      continue;
    if (c >= 'a' && c <= 'z')
      continue;
    if (c >= 'A' && c <= 'Z')
      continue;
    if (c >= '0' && c <= '9')
      continue;
    return false;
  }

  return true;
}

static bool Tokenizer_isnum(Tokenizer* t) {
  if (t->cur.len == 0)
    return false;

  u8 c = Tokenizer_peek_char(t);
  if (c == '+' || c == '-')
    return true;
  if (c >= '0' && c <= '9')
    return true;

  return false;
}

static Str Tokenizer_advance_num(Tokenizer* t, bool* is_float) {
  *is_float = false;
  if (t->cur.len == 0)
    return BytesZero;

  Str out = t->cur;
  out.len = 0;

  u8 c = Tokenizer_peek_char(t);
  if (c == '+' || c == '-') {
    Tokenizer_advance_char(t);
    out.len++;
  }

  bool is_prefixed = false;

  if (t->cur.len >= 2) {
    Str prefix  = bytes_peek(t->cur, 2);
    is_prefixed = str_eq(prefix, Str("0b")) || str_eq(prefix, Str("0o")) ||
                  str_eq(prefix, Str("0x"));
    if (is_prefixed) {
      Tokenizer_advance_char(t);
      Tokenizer_advance_char(t);
      out.len++;
      out.len++;
    }
  }

  // Advance until whitespace or punctuation (except dot) or EOS
  // If !is_prefixed, check if it's a float

  while (t->cur.len) {
    u8 c = Tokenizer_peek_char(t);
    if (Tokenizer_is_whitespace(c))
      break;
    int p = Tokenizer_punct(c);
    if (p > 0 && p != Token_DOT)
      break;
    if (!is_prefixed && (c == '.' || c == 'e' || c == 'E'))
      *is_float = true;

    Tokenizer_advance_char(t);
    out.len++;
  }

  return out;
}

static void Tokenizer_skip_whitespace(Tokenizer* t) {
  while (t->cur.len) {
    u8 c = Tokenizer_peek_char(t);

    if (c == '\n') {
      // Newline
      Tokenizer_advance_line(t);
    } else if (Tokenizer_is_whitespace(c)) {
      // Whitespace
      Tokenizer_advance_char(t);
    } else if (t->cur.len >= 2 && t->cur.buf[0] == '/' &&
               t->cur.buf[1] == '/') {
      // Comment is skipped until end of string or end of line
      Tokenizer_advance_char(t);  // /
      Tokenizer_advance_char(t);  // /
      while (t->cur.len && Tokenizer_peek_char(t) != '\n')
        Tokenizer_advance_char(t);
      if (t->cur.len)
        Tokenizer_advance_line(t);
      continue;
    } else {
      // Real token
      break;
    }
  }
}

static void Tokenizer_token_finalize(Tokenizer* t, DataencParseToken* tok,
                                     int token, Str str) {
  tok->token      = token;
  tok->lineno     = t->lineno;
  tok->lineoffset = t->lineoffset - str.len;
  tok->contents   = str;
}

Str Tokenizer_strlit(Tokenizer* t) {
  if (t->cur.len == 0)
    return BytesZero;

  if (Tokenizer_peek_char(t) != '"')
    return BytesZero;

  Str out = t->cur;
  out.len = 0;

  Tokenizer_advance_char(t);  // "
  out.len++;

  while (t->cur.len) {
    if (Tokenizer_peek_char(t) == '\\') {
      if (t->cur.len < 2)
        return BytesZero;
      Tokenizer_advance_char(t);
      Tokenizer_advance_char(t);
      out.len++;
      out.len++;
      continue;
    }

    if (Tokenizer_peek_char(t) == '"') {
      Tokenizer_advance_char(t);
      out.len++;
      break;
    }

    Tokenizer_advance_char(t);
    out.len++;
  }

  return out;
}

static Str Tokenizer_advance_token(Tokenizer* t) {
  if (t->cur.len == 0)
    return BytesZero;

  Str out = t->cur;
  out.len = 0;
  while (t->cur.len) {
    u8 c = Tokenizer_peek_char(t);
    if (Tokenizer_is_whitespace(c))
      break;
    if (Tokenizer_punct(c))
      break;
    Tokenizer_advance_char(t);
    out.len++;
  }

  return out;
}

TokenizerStatus Tokenizer_next(Tokenizer* t, DataencParseToken* tok) {
  Tokenizer_skip_whitespace(t);

  if (t->cur.len == 0)
    return Tokenizer_END;

  ZERO(tok);

  // Punctuation
  {
    Str s     = bytes_peek(t->cur, 1);
    int token = Tokenizer_punct(s.buf[0]);
    if (token) {
      Tokenizer_advance_char(t);
      Tokenizer_token_finalize(t, tok, token, s);
      return 0;
    }
  }

  // String literal
  if (t->cur.buf[0] == '"') {
    Str lit = Tokenizer_strlit(t);
    if (lit.len < 2 || lit.buf[lit.len - 1] != '"') {
      return Tokenizer_INVALID_STR;
    } else {
      Tokenizer_token_finalize(t, tok, Token_LITERAL_STRING, lit);
      return 0;
    }
  }

  // Numeric literal
  if (Tokenizer_isnum(t)) {
    bool is_float;
    Str  tokstr = Tokenizer_advance_num(t, &is_float);
    if (is_float) {
      if (float_from_str(&tok->fnum, tokstr))
        return Tokenizer_INVALID_FLOAT;
      Tokenizer_token_finalize(t, tok, Token_LITERAL_FLOAT, tokstr);
      return 0;
    } else {
      if (int_from_str(&tok->inum, tokstr))
        return Tokenizer_INVALID_INT;
      Tokenizer_token_finalize(t, tok, Token_LITERAL_INT, tokstr);
      return 0;
    }
  }

  // Consume an alphanumeric token
  Str tokstr = Tokenizer_advance_token(t);

  // Reserved words
  {
    for (usize i = 0; i < ARRAY_LEN(reserved_words); ++i) {
      Str resv = Bytes(reserved_words[i].word, reserved_words[i].len);
      if (str_eq(resv, tokstr)) {
        Tokenizer_token_finalize(t, tok, reserved_words[i].token, resv);
        return 0;
      }
    }
  }

  // Name
  if (!Tokenizer_valid_name(tokstr))
    return Tokenizer_INVALID_NAME;
  Tokenizer_token_finalize(t, tok, Token_NAME, tokstr);

  return 0;
}

void DataencParseToken_log(DataencParseToken* tok) {
  if (tok->token == Token_LITERAL_FLOAT) {
    LOG("%" PRIStr " (%d) val=%f %d:%d", StrPRI(tok->contents), tok->token,
        tok->fnum, (int)tok->lineno, (int)tok->lineoffset);
  } else if (tok->token == Token_LITERAL_INT) {
    LOG("%" PRIStr " (%d) val=%" PRIi64 " %d:%d", StrPRI(tok->contents),
        tok->token, tok->inum, (int)tok->lineno, (int)tok->lineoffset);
  } else {
    LOG("%" PRIStr " (%d) %d:%d", StrPRI(tok->contents), tok->token,
        (int)tok->lineno, (int)tok->lineoffset);
  }
}
