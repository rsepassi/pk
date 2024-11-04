# https://github.com/microsoft/mimalloc
# https://microsoft.github.io/mimalloc/

HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
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
OBJS := $(SRCS:.c=.o)
CFLAGS += -Wall -Werror -fvisibility=hidden -ftls-model=local-dynamic

libmimalloc.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

clean:
	rm -f *.a src/*.o .build
