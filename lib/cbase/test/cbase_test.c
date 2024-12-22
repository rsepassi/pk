#include "allocator.h"
#include "ascii.h"
#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "queue.h"
#include "stdmacros.h"
#include "stdtypes.h"
#include "stdtime.h"
#include "str.h"
#include "unity.h"

#ifdef BYTE_ORDER_LE
#define FOOBAR 77
#else
#define FOOBAR 66
#endif

void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}

void test_macros(void) {
  CHECK(MIN(1, 1024) == 1);
  CHECK(MIN(1, -1024) == -1024);
  CHECK(MAX(1, 1024) == 1024);
  CHECK(MAX(1, -1024) == 1);
  CHECK(ABS(1024) == 1024);
  CHECK(ABS(-1024) == 1024);

  {
    u64 buf[32];
    CHECK(ARRAY_LEN(buf) == 32);
    STATIC_CHECK(ARRAY_LEN(buf) == 32);
  }

  STATIC_CHECK(STRLEN("hi") == 2);

  {
    typedef struct {
      u64 a;
      u64 b;
      u64 c;
    } Foo;

    Foo a = {7, 8, 9};
    CHECK(CONTAINER_OF(&a.b, Foo, b)->c == 9);
  }

  {
    u8  x[128];
    u8* y = CBASE_ALIGN(&x[7], 64);
    CHECK(y > &x[7]);
    CHECK((uptr)y % 64 == 0);
    u8* z = CBASE_ALIGNB(&x[65], 64);
    CHECK(z < &x[65]);
    CHECK((uptr)z % 64 == 0);
  }

  CHECK(CLAMP(10, 20, 30) == 20);
  CHECK(CLAMP(10, 40, 30) == 30);
  CHECK(CLAMP(10, 1, 30) == 10);

  CHECK(IS_ODD(1));
  CHECK(IS_EVEN(2));

  {
    u8 x = 38;  // 0b100110
    CHECK(BITGET(x, 0) == 0);
    CHECK(BITGET(x, 1) == 1);
    CHECK(BITGET(x, 2) == 1);
    CHECK(BITGET(x, 3) == 0);
    CHECK(BITGET(x, 4) == 0);
    CHECK(BITGET(x, 5) == 1);

    CHECK(BITSET(x, 4) == 54);
    CHECK(BITCLEAR(x, 5) == 6);
    CHECK(BITTOGGLE(x, 5) == 6);
    CHECK(BITTOGGLE(x, 0) == 39);
  }

  {
    u32 x = 24845;
    CHECK(SWAP_U32(x) == 224460800);

    u8 els[4];
    memcpy(els, &x, 4);
    u8 tmp   = els[0];
    els[0]   = els[3];
    els[3]   = tmp;
    tmp      = els[1];
    els[1]   = els[2];
    els[2]   = tmp;
    u32 swap = *(u32*)els;
    CHECK(SWAP_U32(x) == swap);
  }

  STATIC_CHECK(FOOBAR == 77);
}

void test_str(void) {
  {
    Bytes z = BytesZero;
    CHECK0(z.buf);
    CHECK0(z.len);
  }

  {
    Str a = Str("hi");
    Str b = Str("hi");
    CHECK(str_eq(a, b));
  }

  {
    char* cstr = "hello world";
    Str   a    = Str0(cstr);
    CHECK(a.len == strlen(cstr));
    CHECK((uptr)a.buf == (uptr)cstr);

    char  buf[32];
    Bytes b = BytesArray(buf);
    bytes_copy(&b, a);

    CHECK(str_eq(a, b));
  }

  {
    char* s = "hi";
    Bytes a = Bytes(s, 2);
    CHECK(str_eq(a, Str("hi")));
  }
}

void test_log(void) {
  LOG("hi");
  LOGS(Str("foo"));
  LOGB(Bytes("ABC", 3));
  CHECK(true, "should never run %d", 7);
  DCHECK(true, "should never run %d", 7);
  STATIC_CHECK(7 > 4);
  STATIC_CHECK(sizeof(u64) == 8);
}

void test_ascii(void) {
  CHECK(ASCII_r == 'r');
  CHECK(ASCII_Z == 'Z');
  CHECK(ASCII_MINUS == '-');
  CHECK(ASCII_TWO == '2');
}

void test_allocator(void) {
  Allocator al = allocator_libc();

  {
    Bytes b;
    CHECK0(allocator_u8(al, &b, 1024));
    allocator_free(al, b);
  }

  {
    Bytes b;
    CHECK0(allocator_alloc(al, &b, 1024, 64));
    CHECK((uptr)b.buf % 64 == 0);
    allocator_free(al, b);
  }
}

void test_containers(void) {
  Allocator al = allocator_libc();

  {
    List a;
    List_init(&a, i32, al, 16);

    i32* a0 = list_get(&a, 0);
    CHECK0(a0);

    i32* an;
    CHECK0(list_addn(&a, 8, (void**)&an));
    for (i32 i = 0; i < 8; ++i) {
      an[i] = i + 22;
    }

    for (i32 i = 0; i < 8; ++i) {
      CHECK(*(i32*)list_get(&a, i) == i + 22);
    }

    CHECK0(list_addn(&a, 16, (void**)&an));

    i32 x = 7;
    list_set(&a, 22, &x);
    CHECK(*(i32*)list_get(&a, 22) == 7);

    list_deinit(&a);
  }

  {
    Hashmap a;
    CHECK0(Hashmap_i32_create(&a, i32, al));
    CHECK0(a.n_buckets);

    {
      i32* x;
      i32* y;
      hashmap_foreach(&a, x, y, { CHECK((*x + *y) == 10); });
    }

    {
      i32           x = 0;
      HashmapStatus s;
      HashmapIter   it = hashmap_put(&a, &x, &s);
      CHECK(it != hashmap_end(&a));
      CHECK(s == HashmapStatus_New);
      CHECK(a.n_buckets == 4);
      *(i32*)hashmap_val(&a, it) = 10;
    }

    for (i32 i = 1; i < 10; ++i) {
      HashmapStatus s;
      HashmapIter   it = hashmap_put(&a, &i, &s);
      CHECK(it != hashmap_end(&a));
      CHECK(s == HashmapStatus_New);
      *(i32*)hashmap_val(&a, it) = 10 - i;
    }

    {
      i32  n = 0;
      i32* x;
      i32* y;
      hashmap_foreach(&a, x, y, {
        CHECK((*x + *y) == 10);
        ++n;
      });
      CHECK(n == 10);
    }

    hashmap_deinit(&a);
  }

  {
    typedef struct {
      i64  x;
      Node n;
    } A;

    Queue q = {0};

    A vals[8] = {0};
    for (usize i = 0; i < ARRAY_LEN(vals); ++i) {
      vals[i].x = i + 22;
      q_enq(&q, &vals[i].n);
    }

    Node* n;
    i64   i = 0;
    while ((n = q_deq(&q))) {
      CHECK(CONTAINER_OF(n, A, n)->x == i + 22);
      ++i;
    }
  }
}

void test_i(Str s, i64 x) {
  i64 out;
  CHECK0(int_from_str(&out, s));
  CHECK(out == x, "got %" PRIi64 " expected %" PRIi64, out, x);
}

void test_ifail(Str s) {
  i64 out;
  CHECK(int_from_str(&out, s) != 0, "expected to fail but passed: %" PRIStr,
        StrPRI(s));
}

void test_parseint(void) {
  test_i(Str("1"), 1);
  test_i(Str("-1"), -1);
  test_i(Str("-308"), -308);
  test_i(Str("+1"), 1);
  test_i(Str("+0123"), 123);
  test_i(Str("0000875432"), 875432);
  test_i(Str("0o667"), 439);
  test_i(Str("0b11001111"), 207);
  test_i(Str("0x00a4f9a10"), 172988944);
  test_i(Str("-0x00a4f9a10"), -172988944);
  test_i(Str("+0x00a4f9a10"), 172988944);
  test_i(Str("+0x00a4_f9a1_0888"), 708562716808);
  test_i(Str("+0x00A4_F9A1_0888"), 708562716808);
  test_i(Str("+0x00a4F9A10888"), 708562716808);
  test_i(Str("222_555_777"), 222555777);

  test_ifail(Str(""));
  test_ifail(Str("+"));
  test_ifail(Str("-"));
  test_ifail(Str("0x"));
  test_ifail(Str("zzz"));
  test_ifail(Str("123zzz"));
  test_ifail(Str("123+"));
}

void test_f(Str s, f64 x) {
  f64 out;
  CHECK0(float_from_str(&out, s), "failed to parse %" PRIStr, StrPRI(s));
  CHECK(out == x, "got %e for %" PRIStr " expected %e", out, StrPRI(s), x);
}

void test_ffail(Str s) {
  f64 out;
  CHECK(float_from_str(&out, s) != 0, "expected to fail but passed: %" PRIStr,
        StrPRI(s));
}

void test_parsefloat(void) {
  // left
  test_f(Str("1"), 1.0);
  // left + right
  test_f(Str("0.1"), 0.1);
  test_f(Str("1.1"), 1.1);
  // left + exp
  test_f(Str("1e3"), 1000.0);
  test_f(Str("1E3"), 1000.0);
  // left + right + exp
  test_f(Str("1.1e3"), 1100.0);
  test_f(Str("1.1E3"), 1100.0);

  test_f(Str("1234.56789"), 1234.56789);
  test_f(Str("1234.111111111111"), 1234.111111111111);
  test_f(Str("0.111111111111"), 0.111111111111);
  test_f(Str("0.111111111111e2"), 11.1111111111);
  test_f(Str("0.111111111111e10"), 1111111111.11);
  test_f(Str("0.111111111111e15"), 111111111111000);
  test_f(Str("111111111111.111111111111"), 111111111111.111111111111);
  test_f(Str("1.7e307"), 1.7e307);
  test_f(Str("1.7e308"), 1.7e308);
  test_f(Str("1.7e-307"), 1.7e-307);

  test_ffail(Str(""));
  test_ffail(Str(".1"));
  test_ffail(Str("e1"));
  test_ffail(Str("1..0"));
  test_ffail(Str("1e1.0"));
  test_ffail(Str("1.7e309"));
  test_ffail(Str("1.7e-308"));
}

void test_stdtime(void) {
  i64 now = stdtime_now_secs();

  char ts_buf[STDTIME_RFC3339_UTC_TIMESTAMP_LEN];
  Str  ts = BytesArray(ts_buf);

  stdtime_rfc3339_utc_format(ts, now);
  LOGS(ts);

  i64 now2;
  CHECK0(stdtime_rfc3339_utc_parse(ts, &now2));

  CHECK(now == now2);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_allocator);
  RUN_TEST(test_ascii);
  RUN_TEST(test_containers);
  RUN_TEST(test_log);
  RUN_TEST(test_str);
  RUN_TEST(test_macros);
  RUN_TEST(test_parseint);
  RUN_TEST(test_parsefloat);
  RUN_TEST(test_stdtime);
  return UNITY_END();
}
