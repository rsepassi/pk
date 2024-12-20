#include "dataenc.h"
#include "log.h"
#include "stdtypes.h"
#include "unity.h"

const char* test_str =
    "import \"foo.denc\";\n"
    "// A comment\n"
    "let x = bool; // A trailing comment\n"
    "let y: bool = true;\n"
    "let MyEnum = enum(u8) { a, b, c, };\n"
    "let B = struct { age u8; height u8; };\n"
    "let A = struct {\n"
    "let ALen: u8 = 4;\n"
    "a u8;\n"
    "b i8;\n"
    "c x;\n"
    "d bitset(u8) { x, y, z };\n"
    "e bitset(u8) { x, y, z, };\n"
    "f enum(u8) { x, y = 3, z };\n"
    "include B;\n"
    "g [4]f32;\n"
    "h []f32;\n"
    "i ?u8;\n"
    "j union {\n"
    "h []f32;\n"
    "i ?u8;\n"
    "};\n"
    "k union(u8) {\n"
    "h []f32;\n"
    "i ?u8;\n"
    "};\n"
    "l union(MyEnum) {\n"
    "h []f32;\n"
    "i ?u8 = 4;\n"
    "};\n"
    "m [ALen]f32;\n"
    "n [ALen]f32 = [1, 2, 3, 4];\n"
    "o B = { .age = 44, .height = 66 };\n"
    "p [ALen]f32 = [1.1, 2e3, -3, 4];\n"
    "};";

const char* test_txt_str =
    "(Foo){\n"
    ".a = 3,\n"
    ".b = 3e3,\n"
    ".c = [ 1, 2, 3 ],\n"
    ".d = { .a = 1, .b = 2, .c = 3 },\n"
    ".e = \"Hello world!\",\n"
    ".f = null,\n"
    ".g = true,\n"
    ".h = false,\n"
    ".i = 1.111,\n"
    "}\n";

void DataencParseTrace(FILE* stream, char* zPrefix);

void write_fn(Str s) { fprintf(stderr, "%" PRIStr, StrPRI(s)); }

void test_dataenc_parse(void) {
  // DataencParseTrace(stderr, "lemon");
  Allocator     al = allocator_libc();
  DataencParser p;
  CHECK0(DataencParser_init(&p, al));
  DataencParseNode* n;
  CHECK0(DataencParser_parse(&p, Str0(test_str), &n));
  CHECK0(DataencParser_pp(write_fn, n));

  DataencParser_deinit(&p);

  LOG("sizeof(DataencParseNode)=%d", (int)sizeof(DataencParseNode));
  STATIC_CHECK(sizeof(DataencParseNode) == 48);
}

void test_dataenc_parsetxt(void) {
  Allocator     al = allocator_libc();
  DataencParser p;
  CHECK0(DataencParser_init(&p, al));
  DataencParseNode* n;
  CHECK0(DataencParser_parsetxt(&p, Str0(test_txt_str), &n));
  CHECK0(DataencParser_pp(write_fn, n));
  DataencParser_deinit(&p);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_dataenc_parse);
  RUN_TEST(test_dataenc_parsetxt);
  return UNITY_END();
}
