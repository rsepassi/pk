// Node constructors used in dataenc_parse.y

#define P DataencParser*
#define N DataencParseNode*
#define Tok DataencParseToken*
#define T(t) DataencNodeType_##t
#define node(t) DataencParse_node(p, T(t))

#define ntype(p, t, c) ntype_(p, DataencTypeType_##t, c)
#define ntok(p, t) ntok_(p, t, T(Token))
#define nimport(p, t) ntok_(p, t, T(Import))
#define nsinc(p, t) ntok_(p, t, T(StructInclude))

N ntype_(P p, DataencTypeType t, N c) {
  N out = node(Type);
  out->xtype.type = t;
  out->xtype.child = c;
  return out;
}

N ntok_(P p, Tok t, DataencNodeType type) {
  N out = DataencParse_node(p, type);
  out->token = t;
  return out;
}

N ndroot(P p, N i, N d) {
  N out = node(DescRoot);
  out->desc_root.imports = i;
  out->desc_root.defs = d;
  return out;
}

N nadd(P p, N l, N n) {
  l = l == 0 ? node(NodeList) : l;
  q_enq(&l->node_list, &n->next);
  return l;
}

N nlet(P p, Tok n, N t, N v) {
  N out;
  out = node(Let);
  out->let.name = n;
  out->let.type = t;
  out->let.value = v;
  return out;
}

N nefield(P p, Tok n, N num) {
  N out = node(EnumField);
  out->enum_field.name = n;
  out->enum_field.num = num;
  return out;
}

N nsfield(P p, Tok n, N t) {
  N out = node(StructField);
  out->struct_field.name = n;
  out->struct_field.type = t;
  return out;
}

N nlit(P p, N c) {
  N out = node(Literal);
  out->lit.child = c;
  return out;
}

N nlitfield(P p, Tok n, N v) {
  N out = node(LiteralField);
  out->lit_field.name = n;
  out->lit_field.value = v;
  return out;
}

N ntxtroot(P p, Tok n, N v) {
  N out = node(TxtRoot);
  out->txt_root.name = n;
  out->txt_root.fields = v;
  return out;
}

N nreft(P p, Tok t) {
  N c = ntok(p, t);
  return ntype(p, typeref, c);
}

N nunion(P p, N t, N f) {
  N c = node(Union);
  c->xunion.tag_type = t;
  c->xunion.fields = f;
  return ntype(p, union, c);
}

N nstruct(P p, N d, N f) {
  N c = node(Struct);
  c->xstruct.defs = d;
  c->xstruct.fields = f;
  return ntype(p, struct, c);
}

N nbitset(P p, N t, N n) {
  N c = node(Bitset);
  c->bitset.type = t;
  c->bitset.names = n;
  return ntype(p, bitset, c);
}

N nenum(P p, N t, N f) {
  N c = node(Enum);
  c->xenum.type = t;
  c->xenum.fields = f;
  return ntype(p, enum, c);
}

N narray(P p, N len, N t) {
  N c = node(Array);
  c->array.type = t;
  c->array.len = len;
  return ntype(p, array, c);
}

N nopt(P p, N t) {
  return ntype(p, optional, t);
}
