#include "allocatormi.h"

#include "log.h"

#include <sys/mman.h>

static int alloc(void* ctx, Bytes* buf, usize sz, usize align) {
  if (sz == 0) {
    mi_free(buf->buf);
    buf->buf = NULL;
  } else {
    void* ptr = buf->len == 0 ? NULL : buf->buf;
    buf->buf = mi_realloc_aligned(ptr, sz, align);
    if (buf->buf == NULL)
      return 1;
  }
  buf->len = sz;
  return 0;
}

static int halloc(void* ctx, Bytes* buf, usize sz, usize align) {
  if (sz == 0) {
    mi_free(buf->buf);
    buf->buf = NULL;
    buf->len = 0;
    return 0;
  }
  void* ptr = buf->len == 0 ? NULL : buf->buf;
  mi_heap_t* h = ctx;
  buf->buf = mi_heap_realloc_aligned(h, ptr, sz, align);
  buf->len = sz;
  if (buf->buf == NULL)
    return 1;
  return 0;
}

static void hdestroy(void* ctx) {
  mi_heap_t* h = ctx;
  mi_heap_destroy(h);
}

Allocator allocatormi_allocator(void) { return (Allocator){0, alloc, 0}; }

Allocator allocatormi_heap(void) { return allocatormi_heap_ex(mi_heap_new()); }

Allocator allocatormi_heap_ex(mi_heap_t* h) {
  return (Allocator){h, halloc, hdestroy};
}

Allocator allocatormi_arena(Bytes arena, bool iszero) {
  mi_arena_id_t id;
  CHECK(mi_manage_os_memory_ex(arena.buf, arena.len, false, false, iszero, -1,
                               true, &id));
  mi_heap_t* h = mi_heap_new_in_arena(id);
  return allocatormi_heap_ex(h);
}

Bytes allocatormi_block_alloc(usize n) {
  u64 sz = 1 << 26;  // 64MiB
  Bytes x = {sz * n,
             mmap(NULL, sz * n, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0)};
  return x;
}

void allocatormi_block_free(Bytes blk) { munmap(blk.buf, blk.len); }
