#pragma once

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? x : y)
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? x : y)
#endif

#ifndef ABS
#define ABS(x) (((x) < 0) ? -(x) : (x))
#endif

#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type*)0)->member)* __mptr = (ptr);                          \
    (type*)((char*)__mptr - offsetof(type, member));                           \
  })
#endif

#define CBASE_ALIGN(x, align) ((x) + (-(uintptr_t)(x) & ((align)-1)))
#define CBASE_ALIGNB(x, align) (((x) + ((align)-1)) & ~((align)-1))

#ifndef CLAMP
#define CLAMP(a, x, b) (((x) < (a)) ? (a) : ((x) > (b)) ? (b) : (x))
#endif

#ifndef IS_ODD
#define IS_ODD(x) ((x) & 1)
#define IS_EVEN(x) (!IS_ODD((x)))
#endif

#ifndef BIT
#define BIT(x) (1 << (x))
#define BITGET(x, i) (((x) >> (i)) & 1)
#define BITSET(x, i) ((x) | (1 << (i)))
#define BITCLEAR(x, i) ((x) & (~(1 << (i))))
#define BITTOGGLE(x, i) ((x) ^ (1 << (i)))
#endif

#ifndef CONCAT
#define CONCAT(a, b) a##b
#define UNIQUENAME(prefix) CONCAT(prefix, __LINE__)
#endif

#ifndef ALIGN
#define ALIGN CBASE_ALIGN
#define ALIGNB CBASE_ALIGNB
#endif

#define SWAP_U32(x)                                                            \
  (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) |       \
   ((x) << 24))
#define SWAP_U16(x) (((x) >> 8) | ((x) << 8))
static inline uint64_t SWAP_U64(uint64_t val) {
  val = ((val << 8) & 0xFF00FF00FF00FF00ULL) |
        ((val >> 8) & 0x00FF00FF00FF00FFULL);
  val = ((val << 16) & 0xFFFF0000FFFF0000ULL) |
        ((val >> 16) & 0x0000FFFF0000FFFFULL);
  return (val << 32) | (val >> 32);
}
