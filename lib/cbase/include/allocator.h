#pragma once

#include "stdtypes.h"
#include "str.h"

typedef int AllocStatus;
#define Alloc_OK 0

typedef AllocStatus (*AllocFn)(void* ctx, Bytes* buf, usize sz, usize align);
typedef void (*AllocDeinitFn)(void* ctx);

typedef struct {
  void* ctx;
  AllocFn alloc;
  AllocDeinitFn deinit;
} Allocator;

#define Alloc_alloc(a, b, T, n)                                                \
  allocator_alloc(a, b, sizeof(T) * n, _Alignof(T))

static inline AllocStatus allocator_u8(Allocator a, Bytes* b, usize sz) {
  b->len = 0;
  return a.alloc(a.ctx, b, sz, 1);
}

static inline AllocStatus allocator_alloc(Allocator a, Bytes* b, usize sz,
                                          usize align) {
  b->len = 0;
  return a.alloc(a.ctx, b, sz, align);
}

static inline AllocStatus allocator_free(Allocator a, Bytes b) {
  return a.alloc(a.ctx, &b, 0, 0);
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
