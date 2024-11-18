HDRS := $(wildcard include/plum/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
CFLAGS += -D_GNU_SOURCE -DPLUM_STATIC

libplum.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -Iinclude/plum -o $@ $<

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
