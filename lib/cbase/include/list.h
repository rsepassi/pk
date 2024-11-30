#pragma once

#include "log.h"
#include "stdtypes.h"

typedef struct {
  Bytes data;
  usize len;
  usize cap;
  Allocator alloc;
  usize elsz;
  usize elalign;
} List;

#define List_init(l, T, a, n) list_init(l, sizeof(T), _Alignof(T), a, n)
#define List_get(l, T, i) ((T*)list_get(l, i))

static inline int list_init(List* ctx, usize elsz, usize elalign,
                            Allocator alloc, usize cap) {
  ctx->data = BytesZero;
  ctx->len = 0;
  ctx->cap = cap;
  ctx->alloc = alloc;
  ctx->elsz = elsz;
  ctx->elalign = elalign;
  if (cap) {
    if (allocator_alloc(alloc, &ctx->data, elsz * cap, elalign))
      return 1;
  }
  return 0;
}

static inline void list_deinit(List* ctx) {
  ctx->len = 0;
  ctx->cap = 0;
  allocator_free(ctx->alloc, ctx->data);
}

static inline int list_reserve(List* ctx, usize n) {
  if (ctx->cap >= n)
    return 0;
  if (allocator_realloc(ctx->alloc, &ctx->data, n * ctx->elsz, ctx->elalign))
    return 1;
  ctx->cap = n;
  return 0;
}

static inline void list_clear(List* ctx) { ctx->len = 0; }

static inline void* list_get(List* ctx, usize i) {
  if (i >= ctx->len)
    return 0;
  usize idx = i * ctx->elsz;
  DCHECK(idx < data.len);
  return &ctx->data.buf[idx];
}

static inline void list_set(List* ctx, usize i, void* val) {
  DCHECK(i < ctx->len);
  usize idx = i * ctx->elsz;
  DCHECK(idx < data.len);
  memcpy(&ctx->data.buf[idx], val, ctx->elsz);
}

static inline int list_addn(List* ctx, usize n, void** out) {
  if (n == 0)
    return 0;
  usize newcap = MAX(ctx->cap, 1);
  while ((ctx->len + n) > newcap)
    newcap *= 2;
  if (list_reserve(ctx, newcap))
    return 1;
  usize i = ctx->len;
  ctx->len += n;
  *out = list_get(ctx, i);
  DCHECK(*out);
  memset(*out, 0, n * ctx->elsz);
  return 0;
}
