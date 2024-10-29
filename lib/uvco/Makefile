HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

DEPS := lib/cbase vendor/libuv vendor/minicoro
DEPS_CFLAGS := \
		`need-cflags lib/cbase` \
		`need-cflags vendor/libuv uv` \
		`need-cflags vendor/minicoro`

libuvco.a: $(OBJS) Makefile | deps
	$(AR) rcs $@ $(OBJS)
	touch .build

%.o: %.c $(HDRS) Makefile | deps
	$(CC) -c $(CFLAGS) -Iinclude $(DEPS_CFLAGS) -o $@ $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	make -C $(ROOTDIR)/$@

clean:
	rm -f *.a src/*.o .build
