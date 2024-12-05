#define MINICORO_IMPL

#ifdef _WIN32
#define MCO_USE_FIBERS
#else
#define MCO_USE_ASM
#endif

#include "minicoro.h"
