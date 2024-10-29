HDRS := $(wildcard include/*.h)
SRCS := $(wildcard src/*.c) $(wildcard src/*.h)
OBJS := $(SRCS:.c=.o)

DEPS := lib/cbase vendor/libuv vendor/minicoro
DEPS_CFLAGS := \
		`need-cflags lib/cbase` \
		`need-cflags vendor/libuv uv` \
		`need-cflags vendor/minicoro`

libuvco.a: $(OBJS) deps Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.o: %.c $(HDRS) deps Makefile
	$(CC) -c $(CFLAGS) -Iinclude $(DEPS_CFLAGS) -o $@ $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	make -C $(ROOTDIR)/$@

clean:
	rm -f *.a src/*.o .build
