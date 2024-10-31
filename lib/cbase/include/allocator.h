#pragma once

#include "stdtypes.h"

typedef int AllocStatus;
#define Alloc_OK 0

typedef AllocStatus (*AllocFn)(void* ctx, Bytes* buf, usize sz, usize align);

typedef struct {
  void* ctx;
  AllocFn alloc;
} Allocator;

#define Alloc_alloc(a, b, T, n) allocator_alloc(a.ctx, b, sizeof(T) * n, alignof(T))

static inline AllocStatus allocator_alloc(Allocator a, Bytes* b, usize sz, usize align) {
  return a.alloc(a.ctx, b, sz, align);
}

static inline AllocStatus allocator_free(Allocator a, Bytes* b) {
  return a.alloc(a.ctx, b, 0, 0);
}

Allocator allocator_libc(void);
