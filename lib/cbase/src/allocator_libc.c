#define _POSIX_C_SOURCE 200809L

#include "allocator.h"
#include "log.h"
#include "stdmacros.h"

#include <stdlib.h>

typedef struct {
  Bytes full;
} Header;

// Every memory allocation will be:
//   Root pointer
//   Padding to fulfill alignment
//   Header
//   Returned aligned pointer

static int alloc_libc(void* ctx, Bytes* buf, usize sz, usize align) {
  (void)ctx;

  bool exists = buf->buf && buf->len > 0;

  // Free
  if (sz == 0) {
    if (exists)
      free(((Header*)((void*)buf->buf - sizeof(Header)))->full.buf);
    *buf = BytesZero;
    return 0;
  }

  usize fullsz = sz + sizeof(Header) + align;

  if (exists) {
    // Reallocation
    Header* h = ((void*)buf->buf - sizeof(Header));
    usize hoffset = (void*)h - (void*)h->full.buf;

    Header hnew = {0};
    void* ptr = h->full.buf;
    ptr = realloc(ptr, fullsz);
    hnew.full.buf = ptr;
    hnew.full.len = fullsz;

    ptr += sizeof(Header);
    ptr = CBASE_ALIGN(ptr, align);

    usize hnewoffset = (ptr - sizeof(Header)) - (void*)hnew.full.buf;
    if (hnewoffset != hoffset)
      memmove(ptr, hnew.full.buf + hoffset + sizeof(Header), MIN(sz, buf->len));

    *(Header*)(ptr - sizeof(Header)) = hnew;
    buf->buf = ptr;
    buf->len = sz;

    return 0;
  } else {
    // Fresh allocation
    Header h = {0};

    void* ptr = NULL;
    ptr = realloc(ptr, fullsz);
    h.full.buf = ptr;
    h.full.len = fullsz;

    ptr += sizeof(Header);
    ptr = CBASE_ALIGN(ptr, align);
    *(Header*)(ptr - sizeof(Header)) = h;
    buf->buf = ptr;
    buf->len = sz;
    return 0;
  }
}

Allocator allocator_libc(void) { return (Allocator){0, alloc_libc, 0}; }

static int bump_alloc(void* ctx, Bytes* buf, usize sz, usize align) {
  BumpAllocator* b = ctx;
  if (sz == 0)
    return 0;

  u8* start = &b->mem.buf[b->i];
  u8* p = start;
  if (align > 1)
    p = ALIGN(p, align);
  usize align_offset = p - start;

  usize fullsz = sz + align_offset;
  if ((start + fullsz) > (b->mem.buf + b->mem.len))
    return 1;

  b->i += fullsz;
  buf->buf = p;
  buf->len = sz;
  return 0;
}

static void bump_deinit(void* ctx) {
  BumpAllocator* b = ctx;
  b->i = 0;
}

Allocator allocator_bump(BumpAllocator* b, Bytes mem) {
  *b = (BumpAllocator){0};
  b->mem = mem;
  return (Allocator){b, bump_alloc, bump_deinit};
}
