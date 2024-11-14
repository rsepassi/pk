#pragma once

#include "allocator.h"
#include "mimalloc.h"

Allocator allocatormi_allocator(void);
Allocator allocatormi_heap(void);
Allocator allocatormi_heap_ex(mi_heap_t *);

// Must be >= 64MiB
Allocator allocatormi_arena(Bytes arena, bool iszero);

// 1 block = 64MiB
Bytes allocatormi_block_alloc(usize nblks);
void allocatormi_block_free(Bytes blk);
