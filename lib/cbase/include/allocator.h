#pragma once

#include "stdtypes.h"
#include "str.h"

#include <stddef.h>

typedef int AllocStatus;
#define Alloc_OK 0

#define Alloc_DefaultAlign(a) (((a) == 0) ? _Alignof(max_align_t) : (a))

typedef AllocStatus (*AllocFn)(void* ctx, Bytes* buf, usize sz, usize align);
typedef void (*AllocDeinitFn)(void* ctx);

typedef struct {
  void*         ctx;
  AllocFn       alloc;
  AllocDeinitFn deinit;
} Allocator;

#define Alloc_alloc(a, b, T, n)                                                \
  allocator_alloc(a, b, sizeof(T) * n, _Alignof(T))
#define Alloc_create(a, pptr)                                                  \
  allocator_create(a, (void**)pptr, sizeof(__typeof__(**pptr)),                \
                   _Alignof(__typeof__(**pptr)))
#define Alloc_destroy(a, ptr)                                                  \
  allocator_destroy(a, (void*)ptr, sizeof(__typeof__(*ptr)))

static inline AllocStatus allocator_u8(Allocator a, Bytes* b, usize sz) {
  b->len = 0;
  return a.alloc(a.ctx, b, sz, Alloc_DefaultAlign(0));
}

static inline AllocStatus allocator_alloc(Allocator a, Bytes* b, usize sz,
                                          usize align) {
  b->len = 0;
  return a.alloc(a.ctx, b, sz, Alloc_DefaultAlign(align));
}

static inline AllocStatus allocator_realloc(Allocator a, Bytes* b, usize sz,
                                            usize align) {
  return a.alloc(a.ctx, b, sz, Alloc_DefaultAlign(align));
}

static inline AllocStatus allocator_create(Allocator a, void** p, usize sz,
                                           usize align) {
  Bytes       b;
  AllocStatus rc = allocator_alloc(a, &b, sz, Alloc_DefaultAlign(align));
  memset(b.buf, 0, b.len);
  *p = b.buf;
  return rc;
}

static inline void allocator_free(Allocator a, Bytes b) {
  a.alloc(a.ctx, &b, 0, 0);
}

static inline void allocator_destroy(Allocator a, void* p, usize sz) {
  Bytes b = {sz, p};
  a.alloc(a.ctx, &b, 0, 0);
}

static inline void allocator_deinit(Allocator a) {
  if (a.deinit)
    a.deinit(a.ctx);
}

Allocator allocator_libc(void);

typedef struct {
  Bytes mem;
  usize i;
} BumpAllocator;
Allocator allocator_bump(BumpAllocator*, Bytes mem);
