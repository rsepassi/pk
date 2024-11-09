HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
CFLAGS += -std=c89 \
					-Wno-deprecated-non-prototype \
					-Wno-return-type \
					-Wno-inconsistent-dllimport \
					-Wno-incompatible-pointer-types \
					-D_GNU_SOURCE

libtai.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

include $(ROOTDIR)/scripts/clean.mk
