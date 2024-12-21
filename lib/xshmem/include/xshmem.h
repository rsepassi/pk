#pragma once

#include "stdtypes.h"

#ifdef _WIN32
#include <windows.h>
#define XSHMEM_PLATFORM_FIELDS HANDLE handle;
#else
#define XSHMEM_PLATFORM_FIELDS                                                 \
  u8 name[255];                                                                \
  u8 name_len;
#endif

typedef struct {
  XSHMEM_PLATFORM_FIELDS
  Bytes mem;
} XShmem;

int  xshmem_create(XShmem* shmem, Str name, usize sz);
int  xshmem_open(XShmem* shmem, Str name, usize sz);
void xshmem_close(XShmem* shmem);
