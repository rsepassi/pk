%include { #include "dataenc_parse_share.h" }
%include { #include "dataenc_parse.inc" }

// Type prefixes
%name DataencParse
%token_prefix Token_

// Parser, Token, Node types
%extra_argument { DataencParser* p }
%token_type     { DataencParseToken* }
%default_type   { DataencParseNode* }

// Hooks from Lemon into the dataenc code
%parse_accept  { dataenc_parse_accept(p); }
%parse_failure { dataenc_parse_fail(p); }
%syntax_error  { dataenc_parse_syntax_error(p, TOKEN); }
%code {
int dataenc_parse_inner2(void* pParser, void*);
int dataenc_parse_inner(void* arg) {
  yyParser p;
  DataencParseInit(&p);
  int rc = dataenc_parse_inner2(&p, arg);
  DataencParseFinalize(&p);
  return rc;
}
}

// We use the same grammar file to define the data description language as well
// as the text literal language. Default values and text representations are
// the same sub-language.
root(L) ::= FORMAT_DESC desc_root(R). { L = R; p->root = L; }
root(L) ::= FORMAT_TEXT text_root(R). { L = R; p->root = L; }

// A descriptor file is a series of imports and definitions.
desc_root(L) ::= imports(I) defs(D).   { L = ndroot(p, I, D); }
imports(L)   ::= .                     { L = 0; }
imports(L)   ::= imports(R) import(N). { L = nadd(p, R, N); }
defs(L)      ::= .                     { L = 0; }
defs(L)      ::= defs(R) def(N).       { L = nadd(p, R, N); }

// An import is a reference to another descriptor file.
import(L) ::= IMPORT LITERAL_STRING(S) SEMICOLON. { L = nimport(p, S); }

// A definition is a constant name binding to a type or value.
def(L)       ::= let_type(R).                                     { L = R; }
def(L)       ::= let_value(R).                                    { L = R; }
let_type(L)  ::= LET NAME(N) EQ type(T) SEMICOLON.                { L = nlet(p, N, T, 0); }
let_value(L) ::= LET NAME(N) COLON type(T) EQ value(V) SEMICOLON. { L = nlet(p, N, T, V); }

// Primitive types
type(L) ::= VOID. { L = ntype(p, void, 0); }
type(L) ::= BOOL. { L = ntype(p, bool, 0); }
type(L) ::= I8.   { L = ntype(p, i8, 0); }
type(L) ::= I16.  { L = ntype(p, i16, 0); }
type(L) ::= I32.  { L = ntype(p, i32, 0); }
type(L) ::= I64.  { L = ntype(p, i64, 0); }
type(L) ::= U8.   { L = ntype(p, u8, 0); }
type(L) ::= U16.  { L = ntype(p, u16, 0); }
type(L) ::= U32.  { L = ntype(p, u32, 0); }
type(L) ::= U64.  { L = ntype(p, u64, 0); }
type(L) ::= F32.  { L = ntype(p, f32, 0); }
type(L) ::= F64.  { L = ntype(p, f64, 0); }

// Fancy integer types
type(L) ::= bitset(R).       { L = R; }
type(L) ::= enum(R).         { L = R; }

// Composite types
type(L) ::= struct(R).       { L = R; }
type(L) ::= array(R).        { L = R; }
type(L) ::= list(R).         { L = R; }
type(L) ::= optional(R).     { L = R; }
type(L) ::= union(R).        { L = R; }
type(L) ::= tagunion(R).     { L = R; }

// Reference a name-bound type
type(L) ::= NAME(T). { L = nreft(p, T); }

// Definitions for fancy integer types
bitset(L)   ::= BITSET LPAREN type(T) RPAREN LBRACE names(N) RBRACE.     { L = nbitset(p, T, N); }
enum(L)     ::= ENUM LPAREN type(T) RPAREN LBRACE enum_fields(F) RBRACE. { L = nenum(p, T, F); }

// Definitions for composite types
struct(L)   ::= STRUCT LBRACE defs(D) fields(F) RBRACE.                  { L = nstruct(p, D, F); }
array(L)    ::= LBRACK numval(A) RBRACK type(T).                         { L = narray(p, A, T); }
list(L)     ::= LBRACK RBRACK type(T).                                   { L = narray(p, 0, T); }
optional(L) ::= QUESTION type(T).                                        { L = nopt(p, T); }
union(L)    ::= UNION LBRACE fields(F) RBRACE.                           { L = nunion(p, 0, F); }
tagunion(L) ::= UNION LPAREN type(T) RPAREN LBRACE fields(F) RBRACE.     { L = nunion(p, T, F); }

// Comma-separated names
names(L) ::= NAME(N).                 { L = nadd(p, 0, ntok(p, N)); }
names(L) ::= names(R) COMMA.          { L = R; }
names(L) ::= names(R) COMMA NAME(N).  { L = nadd(p, R, ntok(p, N)); }

// Comma-separated enum fields
enum_fields(L) ::= enum_field(F).                       { L = nadd(p, 0, F); }
enum_fields(L) ::= enum_fields(R) COMMA.                { L = R; }
enum_fields(L) ::= enum_fields(R) COMMA enum_field(F).  { L = nadd(p, R, F); }

// An enum field is a name, and an optional numeric value
enum_field(L) ::= NAME(N).              { L = nefield(p, N, 0); }
enum_field(L) ::= NAME(N) EQ numval(M). { L = nefield(p, N, M); }

// Structs and unions are composed of fields
fields(L)      ::= .                                    { L = 0; }
fields(L)      ::= fields(R) field(F).                  { L = nadd(p, R, F); }
field(L)       ::= INCLUDE NAME(N) SEMICOLON.           { L = nsfield(p, N, 0); L->struct_field.include = true; }
field(L)       ::= field_spec(F) SEMICOLON.             { L = F; }
field(L)       ::= field_spec(F) EQ value(V) SEMICOLON. { L = F; L->struct_field.value = V; }
field_spec(L)  ::= NAME(N).                             { L = nsfield(p, N, 0); }
field_spec(L)  ::= NAME(N) type(T).                     { L = nsfield(p, N, T); }

// Values are either literals or named references to values
value(L) ::= NAME(N).    { L = ntok(p, N); }
value(L) ::= literal(R). { L = R; }

// Numeric values are either numeric literals or named references to numeric values
numval(L) ::= number(N). { L = N; }
numval(L) ::= NAME(N).   { L = ntok(p, N); }

// Each of the types has a literal representation, except for void
literal(L) ::= number(R).         { L = nlit(p, R); }
literal(L) ::= LITERAL_STRING(R). { L = nlit(p, ntok(p, R)); }
literal(L) ::= LITERAL_NULL(R).   { L = nlit(p, ntok(p, R)); }
literal(L) ::= LITERAL_TRUE(R).   { L = nlit(p, ntok(p, R)); }
literal(L) ::= LITERAL_FALSE(R).  { L = nlit(p, ntok(p, R)); }
literal(L) ::= literal_array(R).  { L = nlit(p, R); L->lit.type = DataencLiteralType_Array; }
literal(L) ::= literal_struct(R). { L = nlit(p, R); L->lit.type = DataencLiteralType_Fields; }

// Numeric literals
number(L)  ::= LITERAL_INT(R).    { L = ntok(p, R); }
number(L)  ::= LITERAL_FLOAT(R).  { L = ntok(p, R); }

// Composite literals
literal_array(L)  ::= LBRACK literals(R) RBRACK.       { L = R; }
literal_struct(L) ::= LBRACE literal_fields(R) RBRACE. { L = R; }

// Comma-separated literals
literals(L) ::= literal(R).                   { L = nadd(p, 0, R); }
literals(L) ::= literals(R) COMMA.            { L = R; }
literals(L) ::= literals(R) COMMA literal(A). { L = nadd(p, R, A); }

// Comma-separated literal fields
literal_fields(L) ::= .                                         { L = 0; }
literal_fields(L) ::= literal_field(R).                         { L = nadd(p, 0, R); }
literal_fields(L) ::= literal_fields(R) COMMA.                  { L = R; }
literal_fields(L) ::= literal_fields(R) COMMA literal_field(F). { L = nadd(p, R, F); }

// A literal field is a field name and value
literal_field(L) ::= DOT NAME(N) EQ value(V). { L = nlitfield(p, N, V); }

// A text document is a struct name and literal fields
text_root(L) ::= LPAREN NAME(N) RPAREN LBRACE literal_fields(F) RBRACE. { L = ntxtroot(p, N, F); }
