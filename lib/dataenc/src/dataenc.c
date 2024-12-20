#include "dataenc.h"

#include "dataenc_parse_tokens.h"
#include "stdmacros.h"
#include "stdtypes.h"
#include "tokenizer.h"

#include <stdlib.h>

void  DataencParse(void*, int, void*, void*);
void* DataencParseAlloc(void*);
void  DataencParseFree(void*, void*);
int   dataenc_parse_inner(void*);

typedef struct {
  DataencParser*     p;
  Str                desc;
  DataencParseNode** root;
  bool               txt;
} LemonArg;

static bool nodeblkfull(Node* b) {
  DataencParseNodeBlk* blk = CONTAINER_OF(b, DataencParseNodeBlk, next);
  return blk->len == ARRAY_LEN(blk->nodes);
}

static bool tokblkfull(Node* b) {
  DataencParseTokenBlk* blk = CONTAINER_OF(b, DataencParseTokenBlk, next);
  return blk->len == ARRAY_LEN(blk->tokens);
}

static DataencParseToken* DataencParse_token(DataencParser* p) {
  if (p->token_blks.tail == NULL || tokblkfull(p->token_blks.tail)) {
    DataencParseTokenBlk* blk;
    CHECK0(Alloc_create(p->al, &blk));
    ZERO(blk);
    q_enq(&p->token_blks, &blk->next);
  }

  DataencParseTokenBlk* blk =
      CONTAINER_OF(p->token_blks.tail, DataencParseTokenBlk, next);
  DataencParseToken* out = &blk->tokens[blk->len];
  blk->len++;
  return out;
}

DataencParseNode* DataencParse_node(DataencParser* p, DataencNodeType t) {
  if (p->node_blks.tail == NULL || nodeblkfull(p->node_blks.tail)) {
    DataencParseNodeBlk* blk;
    CHECK0(Alloc_create(p->al, &blk));
    ZERO(blk);
    q_enq(&p->node_blks, &blk->next);
  }

  DataencParseNodeBlk* blk =
      CONTAINER_OF(p->node_blks.tail, DataencParseNodeBlk, next);
  DataencParseNode* out = &blk->nodes[blk->len];
  blk->len++;
  out->type = t;

  return out;
}

int dataenc_parse_inner2(void* pParser, void* varg) {
  LemonArg* arg = varg;

  DataencParser*     p      = arg->p;
  Str                desc   = arg->desc;
  DataencParseNode** root   = arg->root;
  bool               is_txt = arg->txt;

  Tokenizer t = {0};
  t.cur       = desc;

  DataencParse(pParser, is_txt ? Token_FORMAT_TEXT : Token_FORMAT_DESC, 0, p);
  while (1) {
    DataencParseToken* tok = DataencParse_token(p);
    int                rc  = Tokenizer_next(&t, tok);
    if (rc == Tokenizer_END)
      break;
    if (rc != 0) {
      LOG("tokenizer err=%d", rc);
      p->syntax_error = true;
      return 1;
    }

    DataencParseToken_log(tok);

    DataencParse(pParser, tok->token, tok, p);

    CHECK(!p->syntax_error);
    CHECK(!p->failed);

    if (p->syntax_error)
      return 1;
    if (p->failed)
      return 1;
  }
  DataencParse(pParser, 0, 0, p);

  CHECK(p->root);
  *root = p->root;

  return 0;
}

int DataencParser_init(DataencParser* p, Allocator al) {
  ZERO(p);
  p->al = al;
  return 0;
}

void DataencParser_deinit(DataencParser* p) {
  Node* n;
  q_drain(&p->node_blks, n, {
    DataencParseNodeBlk* blk = CONTAINER_OF(n, DataencParseNodeBlk, next);
    Alloc_destroy(p->al, blk);
  });
  q_drain(&p->token_blks, n, {
    DataencParseTokenBlk* blk = CONTAINER_OF(n, DataencParseTokenBlk, next);
    Alloc_destroy(p->al, blk);
  });
}

int DataencParser_parse(DataencParser* p, Str s, DataencParseNode** n) {
  LemonArg arg = {p, s, n, 0};
  return dataenc_parse_inner(&arg);
}

int DataencParser_parsetxt(DataencParser* p, Str s, DataencParseNode** n) {
  LemonArg arg = {p, s, n, 1};
  return dataenc_parse_inner(&arg);
}

void dataenc_parse_accept(DataencParser* p) {}
void dataenc_parse_fail(DataencParser* p) { p->failed = true; }
void dataenc_parse_syntax_error(DataencParser* p, DataencParseToken* t) {
  p->syntax_error = true;
  DataencParseToken_log(t);
  LOG("syntax error");
}
