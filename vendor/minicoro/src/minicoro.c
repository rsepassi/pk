#define MINICORO_IMPL
#define MCO_USE_VMEM_ALLOCATOR

#ifdef _WIN32
#define MCO_USE_FIBERS
#else
#define MCO_USE_ASM
#endif

#include "minicoro.h"
