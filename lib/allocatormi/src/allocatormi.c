#include "allocatormi.h"

#include "log.h"

static int alloc(void* ctx, Bytes* buf, usize sz, usize align) {
  (void)ctx;

  if (sz == 0) {
    mi_free(buf->buf);
    *buf = BytesZero;
  } else {
    void* ptr = buf->len == 0 ? NULL : buf->buf;
    buf->buf  = mi_realloc_aligned(ptr, sz, align);
    if (buf->buf == NULL)
      return 1;
    buf->len = sz;
  }
  return 0;
}

Allocator allocatormi_allocator(void) { return (Allocator){0, alloc, 0}; }
