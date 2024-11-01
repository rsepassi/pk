#include "allocator.h"

#include <stdlib.h>
#include <mm_malloc.h>

static int alloc_libc(void* ctx, Bytes* buf, usize sz, usize align) {
  bool exists = buf->buf && buf->len > 0;

  // Free
  if (sz == 0) {
    if (exists) free(buf->buf);
    buf->buf = 0;
    buf->len = 0;
    return 0;
  }

  // Unaligned realloc
  if (align <= 1) {
    void* ptr = (void*)buf->buf;
    ptr = realloc(ptr, sz);
    if (!ptr) return 1;
    buf->buf = ptr;
    buf->len = sz;
    return 0;
  }

  // Aligned alloc
  if (!exists) {
    void* ptr;
    if (posix_memalign(&ptr, align, sz) != 0) return 1;
    buf->buf = ptr;
    buf->len = sz;
    return 0;
  }

  // Aligned realloc
  void* ptr;
  if (posix_memalign(&ptr, align, sz) != 0) return 1;
  memcpy(ptr, buf->buf, buf->len);
  free(buf->buf);
  buf->buf = ptr;
  buf->len = sz;

  return 0;
}

Allocator allocator_libc(void) { return (Allocator){0, alloc_libc}; }
