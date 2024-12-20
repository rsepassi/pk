#pragma once

#include "dataenc_parse_share.h"

int  DataencParser_init(DataencParser* p, Allocator al);
void DataencParser_deinit(DataencParser* p);
int  DataencParser_parse(DataencParser* p, Str s, DataencParseNode** n);
int  DataencParser_parsetxt(DataencParser* p, Str s, DataencParseNode** n);

typedef void (*DataencWriteFn)(Str s);
int DataencParser_pp(DataencWriteFn f, DataencParseNode* n);
