#include "dataenc.h"

#define N      DataencParseNode*
#define T(t)   DataencNodeType_##t
#define PP(s)  pp->write(s)
#define PPS(s) pp->write(Str(s))
#define PPNL() pp_nl(pp);
#define PPCALL(__name, n)                                                      \
  do {                                                                         \
    if (pp_##__name(pp, n))                                                    \
      return 1;                                                                \
  } while (0)
#define PPFN(__name, code)                                                     \
  static int pp_##__name(PPCtx* pp, DataencParseNode* n) {                     \
    code;                                                                      \
    return 0;                                                                  \
  }

typedef struct {
  int            indent;
  DataencWriteFn write;
} PPCtx;
static void pp_push(PPCtx* pp) { pp->indent += 2; }
static void pp_pop(PPCtx* pp) { pp->indent -= 2; }
static void pp_nl(PPCtx* pp) {
  pp->write(Str("\n"));
  for (int i = 0; i < pp->indent; ++i)
    pp->write(Str(" "));
}

static int pp_type(PPCtx* pp, DataencParseNode* n);
static int pp_lit(PPCtx* pp, DataencParseNode* n);

PPFN(token, { PP(n->token->contents); });

PPFN(value, {
  if (n->type == T(Token))
    PPCALL(token, n);
  else if (n->type == T(Literal))
    PPCALL(lit, n);
  else
    CHECK(false);
});

PPFN(lit_array, {
  PPS("[");
  N   f;
  int i = 0;
  q_foreach(&n->node_list, f, next, {
    if (i)
      PPS(", ");
    PPCALL(lit, f);
    ++i;
  });
  PPS("]");
});

PPFN(array, {
  PPS("[");
  if (n->array.len)
    PPCALL(value, n->array.len);
  PPS("]");
  PPCALL(type, n->array.type);
});

PPFN(ptype, {
  if (!n)
    return 0;
  PPS("(");
  PPCALL(type, n);
  PPS(")");
});

PPFN(bitset, {
  PPS("bitset");
  PPCALL(ptype, n->bitset.type);
  PPS(" {");
  int i = 0;
  N   f;
  q_foreach(&n->bitset.names->node_list, f, next, {
    if (i)
      PPS(", ");
    PPCALL(token, f);
    ++i;
  });
  PPS("}");
});

PPFN(def, {
  PPS("let ");
  PP(n->let.name->contents);
  if (n->let.value) {
    PPS(": ");
    PPCALL(type, n->let.type);
    PPS(" = ");
    PPCALL(value, n->let.value);
  } else {
    PPS(" = ");
    PPCALL(type, n->let.type);
  }
  PPS(";");
});

PPFN(defs, {
  N   f;
  int i = 0;
  q_foreach(&n->node_list, f, next, {
    if (i)
      PPNL();
    PPCALL(def, f);
    ++i;
  });
});

PPFN(enum_field, {
  PP(n->enum_field.name->contents);
  if (n->enum_field.num) {
    PPS(" = ");
    PPCALL(value, n->enum_field.num);
  }
});

PPFN(enum, {
  PPS("enum");
  PPCALL(ptype, n->xenum.type);
  PPS(" {");
  pp_push(pp);
  N f;
  q_foreach(&n->xenum.fields->node_list, f, next, {
    PPNL();
    PPCALL(enum_field, f);
    PPS(",");
  });
  pp_pop(pp);
  PPNL();
  PPS("}");
});

PPFN(fields, {
  N f;
  q_foreach(&n->node_list, f, next, {
    PPNL();
    if (f->struct_field.include)
      PPS("include ");
    PP(f->struct_field.name->contents);
    if (f->struct_field.type) {
      PPS(" ");
      PPCALL(type, f->struct_field.type);
    }
    if (f->struct_field.value) {
      PPS(" = ");
      PPCALL(value, f->struct_field.value);
    }
    PPS(";");
  });
});

PPFN(imports, {
  N f;
  q_foreach(&n->node_list, f, next, {
    PPS("import ");
    PPCALL(token, f);
    PPS(";");
    PPNL();
  });
});

PPFN(desc, {
  if (n->desc_root.imports)
    PPCALL(imports, n->desc_root.imports);
  if (n->desc_root.defs)
    PPCALL(defs, n->desc_root.defs);
  PPNL();
});

PPFN(lit_field, {
  PPS(".");
  PP(n->lit_field.name->contents);
  PPS(" = ");
  PPCALL(value, n->lit_field.value);
});

PPFN(lit_fields, {
  PPS("{");
  pp_push(pp);
  N f;
  q_foreach(&n->node_list, f, next, {
    PPNL();
    PPCALL(lit_field, f);
    PPS(",");
  });
  pp_pop(pp);
  PPNL();
  PPS("}");
});

PPFN(lit, {
  switch (n->lit.type) {
    case DataencLiteralType_Token:
      PPCALL(token, n->lit.child);
      break;
    case DataencLiteralType_Array:
      PPCALL(lit_array, n->lit.child);
      break;
    case DataencLiteralType_Fields:
      PPCALL(lit_fields, n->lit.child);
      break;
  }
});

PPFN(struct, {
  PPS("struct");
  PPS(" {");
  pp_push(pp);
  if (n->xstruct.defs) {
    PPNL();
    PPCALL(defs, n->xstruct.defs);
  }
  PPCALL(fields, n->xstruct.fields);
  pp_pop(pp);
  PPNL();
  PPS("}");
});

PPFN(union, {
  PPS("union");
  PPCALL(ptype, n->xunion.tag_type);
  PPS(" {");
  pp_push(pp);
  PPCALL(fields, n->xunion.fields);
  pp_pop(pp);
  PPNL();
  PPS("}");
});

PPFN(type, {
  switch (n->xtype.type) {
    case DataencTypeType_void:
      PPS("void");
      break;
    case DataencTypeType_bool:
      PPS("bool");
      break;
    case DataencTypeType_i8:
      PPS("i8");
      break;
    case DataencTypeType_i16:
      PPS("i16");
      break;
    case DataencTypeType_i32:
      PPS("i32");
      break;
    case DataencTypeType_i64:
      PPS("i64");
      break;
    case DataencTypeType_u8:
      PPS("u8");
      break;
    case DataencTypeType_u16:
      PPS("u16");
      break;
    case DataencTypeType_u32:
      PPS("u32");
      break;
    case DataencTypeType_u64:
      PPS("u64");
      break;
    case DataencTypeType_f32:
      PPS("f32");
      break;
    case DataencTypeType_f64:
      PPS("f64");
      break;
    case DataencTypeType_bitset:
      PPCALL(bitset, n->xtype.child);
      break;
    case DataencTypeType_enum:
      PPCALL(enum, n->xtype.child);
      break;
    case DataencTypeType_struct:
      PPCALL(struct, n->xtype.child);
      break;
    case DataencTypeType_array:
      PPCALL(array, n->xtype.child);
      break;
    case DataencTypeType_optional:
      PPS("?");
      PPCALL(type, n->xtype.child);
      break;
    case DataencTypeType_union:
      PPCALL(union, n->xtype.child);
      break;
    case DataencTypeType_typeref:
      PPCALL(token, n->xtype.child);
      break;
  }
});

PPFN(txt, {
  PPS("(");
  PP(n->txt_root.name->contents);
  PPS(")");
  PPCALL(lit_fields, n->txt_root.fields);
  PPS("\n");
});

int DataencParser_pp(DataencWriteFn f, DataencParseNode* n) {
  (void)pp_push;
  (void)pp_pop;
  PPCtx ctx = {0};
  ctx.write = f;
  if (n->type == T(TxtRoot))
    return pp_txt(&ctx, n);
  if (n->type == T(DescRoot))
    return pp_desc(&ctx, n);
  return 1;
}
