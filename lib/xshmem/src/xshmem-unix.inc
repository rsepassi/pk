#include "xshmem.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int xshmem_create2(XShmem* shmem, Str name, usize sz, int flags) {
  if (name.len > 254)
    return 1;
  memcpy(shmem->name, name.buf, name.len);
  shmem->name[name.len] = 0;
  shmem->name_len       = (u8)(name.len + 1);

  int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
  int fd = shm_open((char*)shmem->name, O_RDWR | flags, mode);
  if (fd < 0)
    return 1;

  if (flags & O_CREAT) {
    if (ftruncate(fd, sz)) {
      close(fd);
      return 1;
    }
  }

  void* base =
      mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED)
    return 1;

  shmem->mem = Bytes(base, sz);
  close(fd);
  return 0;
}

int xshmem_create(XShmem* shmem, Str name, usize sz) {
  return xshmem_create2(shmem, name, sz, O_CREAT);
}

int xshmem_open(XShmem* shmem, Str name, usize sz) {
  return xshmem_create2(shmem, name, sz, 0);
}

void xshmem_close(XShmem* shmem) {
  munmap(shmem->mem.buf, shmem->mem.len);
  shm_unlink((char*)shmem->name);
}
