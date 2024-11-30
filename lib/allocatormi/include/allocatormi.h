#pragma once

#include "allocator.h"
#include "mimalloc.h"

Allocator allocatormi_allocator(void);
Allocator allocatormi_heap(void);
Allocator allocatormi_heap_ex(mi_heap_t*);
