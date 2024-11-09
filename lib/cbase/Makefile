HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

libcbase.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

include $(ROOTDIR)/scripts/clean.mk
