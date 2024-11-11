HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

DEPS := lib/cbase vendor/sodium
DEPS_CFLAGS := \
		`need-cflags lib/cbase` \
		`need-cflags vendor/sodium`

libcrypto.a: $(OBJS) Makefile | deps
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile | deps
	$(CC) -c -o $@ -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $<

include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
