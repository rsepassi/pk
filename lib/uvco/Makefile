HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

DEPS := lib/cbase vendor/libuv vendor/minicoro
DEPS_CFLAGS := \
		`need-cflags lib/cbase` \
		`need-cflags vendor/libuv uv` \
		`need-cflags vendor/minicoro`

libuvco.a: $(OBJS) Makefile | deps
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile | deps
	$(CC) -c $(CFLAGS) -Iinclude $(DEPS_CFLAGS) -o $@ $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	make -C $(ROOTDIR)/$@

include $(ROOTDIR)/scripts/clean.mk
