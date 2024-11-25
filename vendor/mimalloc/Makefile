# https://github.com/microsoft/mimalloc
# https://microsoft.github.io/mimalloc/

SRCS := \
	src/alloc-aligned.c \
	src/alloc-posix.c \
	src/alloc.c \
	src/arena.c \
	src/bitmap.c \
	src/heap.c \
	src/init.c \
	src/libc.c \
	src/options.c \
	src/os.c \
	src/page.c \
	src/random.c \
	src/segment-map.c \
	src/segment.c \
	src/stats.c \
	src/prim/prim.c
CFLAGS += -Wall -Werror -fvisibility=hidden -ftls-model=local-dynamic \
					-Wno-unknown-pragmas -Wno-conversion

ifdef VALGRIND
CFLAGS += -DMI_STAT=2 -DMI_SECURE=4 -DMI_DEBUG=3 -DMI_TRACK_VALGRIND=1
endif

CLEAN_EXTRAS := src/prim/*.o src/prim/*.obj

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
