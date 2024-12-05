#include "allocator.h"
#include "ascii.h"
#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "queue.h"
#include "stdmacros.h"
#include "stdtypes.h"
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
    Str   a    = str_from_c(cstr);
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

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_allocator);
  RUN_TEST(test_ascii);
  RUN_TEST(test_containers);
  RUN_TEST(test_log);
  RUN_TEST(test_str);
  RUN_TEST(test_macros);
  return UNITY_END();
}
