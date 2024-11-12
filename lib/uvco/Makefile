HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
DEPS := lib/cbase vendor/uv vendor/minicoro
include $(ROOTDIR)/scripts/deps.mk

libuvco.a: $(OBJS) Makefile | deps
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile | deps
	$(CC) -c $(CFLAGS) -Iinclude $(DEPS_CFLAGS) -o $@ $<

include $(ROOTDIR)/scripts/clean.mk
