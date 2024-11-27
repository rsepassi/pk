#define _POSIX_C_SOURCE

#include "allocator.h"
#include "log.h"
#include "stdmacros.h"

#include <mm_malloc.h>
#include <stdlib.h>

static int alloc_libc(void* ctx, Bytes* buf, usize sz, usize align) {
  (void)ctx;

  bool exists = buf->buf && buf->len > 0;

  // Free
  if (sz == 0) {
    if (exists)
      free(buf->buf);
    buf->buf = 0;
    buf->len = 0;
    return 0;
  }

  // Unaligned realloc
  if (align <= 1) {
    void* ptr = (void*)buf->buf;
    ptr = realloc(ptr, sz);
    if (!ptr)
      return 1;
    buf->buf = ptr;
    buf->len = sz;
    return 0;
  }

#ifdef _WIN32
  CHECK(false, "unsupported");
#else
  // Aligned alloc
  if (!exists) {
    void* ptr;
    if (posix_memalign(&ptr, align, sz) != 0)
      return 1;
    buf->buf = ptr;
    buf->len = sz;
    return 0;
  }

  // Aligned realloc
  void* ptr;
  if (posix_memalign(&ptr, align, sz) != 0)
    return 1;
  memcpy(ptr, buf->buf, buf->len);
  free(buf->buf);
  buf->buf = ptr;
  buf->len = sz;
#endif

  return 0;
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
  CHECK((uptr)p % align == 0);
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
