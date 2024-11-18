HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

libcbase.a: $(OBJS) $(SRCS) $(HDRS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
