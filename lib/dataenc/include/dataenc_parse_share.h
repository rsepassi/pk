#pragma once

#include "queue.h"
#include "stdtypes.h"

typedef struct {
  int   token;
  usize lineno;
  usize lineoffset;
  Str   contents;
  union {
    i64 inum;
    f64 fnum;
  };
} DataencParseToken;

typedef enum {
  DataencNodeType_DescRoot,
  DataencNodeType_TxtRoot,
  DataencNodeType_NodeList,
  DataencNodeType_Import,
  DataencNodeType_Let,
  DataencNodeType_Struct,
  DataencNodeType_StructField,
  DataencNodeType_Type,
  DataencNodeType_Bitset,
  DataencNodeType_Enum,
  DataencNodeType_EnumField,
  DataencNodeType_Array,
  DataencNodeType_Union,
  DataencNodeType_Token,
  DataencNodeType_Literal,
  DataencNodeType_LiteralField,
} DataencNodeType;

typedef enum {
  DataencTypeType_void,
  DataencTypeType_bool,
  DataencTypeType_i8,
  DataencTypeType_i16,
  DataencTypeType_i32,
  DataencTypeType_i64,
  DataencTypeType_u8,
  DataencTypeType_u16,
  DataencTypeType_u32,
  DataencTypeType_u64,
  DataencTypeType_f32,
  DataencTypeType_f64,
  DataencTypeType_bitset,
  DataencTypeType_enum,
  DataencTypeType_struct,
  DataencTypeType_array,
  DataencTypeType_optional,
  DataencTypeType_union,
  DataencTypeType_typeref,
} DataencTypeType;

typedef struct DataencParseNode DataencParseNode;

typedef struct {
  DataencParseNode* imports;
  DataencParseNode* defs;
} DataencParseRoot;

typedef struct {
  DataencTypeType   type;
  DataencParseNode* child;
} DataencParseType;

typedef struct {
  DataencParseToken* name;
  DataencParseNode*  fields;
} DataencParseTxtRoot;

typedef struct {
  DataencParseToken* name;
  DataencParseNode*  type;
  DataencParseNode*  value;
} DataencParseLet;

typedef struct {
  DataencParseNode* defs;
  DataencParseNode* fields;
} DataencParseStruct;

typedef enum {
  DataencLiteralType_Token,
  DataencLiteralType_Array,
  DataencLiteralType_Fields,
} DataencLiteralType;

typedef struct {
  DataencLiteralType type;
  DataencParseNode*  child;
} DataencParseLiteral;

typedef struct {
  DataencParseToken* name;
  DataencParseNode*  num;
} DataencParseEnumField;

typedef struct {
  DataencParseToken* name;
  DataencParseNode*  value;
} DataencParseLiteralField;

typedef struct {
  DataencParseToken* name;
  DataencParseNode*  type;
  DataencParseNode*  value;
  bool               include;
} DataencParseStructField;

typedef struct {
  DataencParseNode* len;
  DataencParseNode* type;
} DataencParseArray;

typedef struct {
  DataencParseNode* type;
  DataencParseNode* names;
} DataencParseBitset;

typedef struct {
  DataencParseNode* type;
  DataencParseNode* fields;
} DataencParseEnum;

typedef struct {
  DataencParseNode* tag_type;
  DataencParseNode* fields;
} DataencParseUnion;

struct DataencParseNode {
  DataencNodeType type;
  Node            next;
  union {
    // Root nodes
    DataencParseRoot    desc_root;
    DataencParseTxtRoot txt_root;
    // Lists
    Queue node_list;
    // Generic
    DataencParseToken* token;
    DataencParseNode*  child;
    // Let bindings
    DataencParseLet let;
    // Types
    DataencParseType   xtype;
    DataencParseStruct xstruct;
    DataencParseArray  array;
    DataencParseBitset bitset;
    DataencParseEnum   xenum;
    DataencParseUnion  xunion;
    // Literal
    DataencParseLiteral lit;
    // Fields
    DataencParseEnumField    enum_field;
    DataencParseStructField  struct_field;
    DataencParseLiteralField lit_field;
  };
};

typedef struct {
  DataencParseNode nodes[1024];
  Node             next;
  u16              len;
} DataencParseNodeBlk;

typedef struct {
  DataencParseToken tokens[1024];
  Node              next;
  u16               len;
} DataencParseTokenBlk;

typedef struct {
  Str               contents;
  bool              failed;
  bool              syntax_error;
  Queue             node_blks;   // DataencParseNodeBlk
  Queue             token_blks;  // DataencParseTokenBlk
  Allocator         al;
  DataencParseNode* root;
} DataencParser;

DataencParseNode* DataencParse_node(DataencParser* p, DataencNodeType t);

void dataenc_parse_accept(DataencParser*);
void dataenc_parse_fail(DataencParser*);
void dataenc_parse_syntax_error(DataencParser* p, DataencParseToken* t);
