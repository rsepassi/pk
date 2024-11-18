HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
DEPS := lib/cbase vendor/mimalloc

liballocatormi.a: $(OBJS) Makefile .deps.ok
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile .deps.ok
	$(CC) -c -o $@ -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $<

include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
