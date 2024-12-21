#include "xshmem.h"

int xshmem_create(XShmem* shmem, Str name, usize sz) {
  char name_buf[255];
  if (name.len > 254)
    return 1;
  memcpy(name_buf, name.buf, name.len);
  name_buf[name.len] = 0;

  shmem->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    0, (DWORD)sz, name_buf);

  if (shmem->handle == NULL)
    return 1;

  // Map the shared memory
  shmem->mem.buf = MapViewOfFile(shmem->handle, FILE_MAP_ALL_ACCESS, 0, 0, sz);

  if (shmem->mem.buf == NULL) {
    CloseHandle(shmem->handle);
    return 1;
  }

  shmem->mem.len = sz;
  return 0;
}

int xshmem_open(XShmem* shmem, Str name, usize sz) {
  char name_buf[255];
  if (name.len > 254)
    return 1;
  memcpy(name_buf, name.buf, name.len);
  name_buf[name.len] = 0;

  shmem->handle = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name_buf);

  if (shmem->handle == NULL)
    return 1;

  shmem->mem.buf = MapViewOfFile(shmem->handle, FILE_MAP_ALL_ACCESS, 0, 0, sz);

  if (shmem->mem.buf == NULL) {
    CloseHandle(shmem->handle);
    return 1;
  }

  shmem->mem.len = sz;
  return 0;
}

void xshmem_close(XShmem* shmem) {
  if (shmem->mem.buf != NULL) {
    UnmapViewOfFile(shmem->mem.buf);
    shmem->mem = BytesZero;
  }

  if (shmem->handle != NULL) {
    CloseHandle(shmem->handle);
    shmem->handle = 0;
  }
}
