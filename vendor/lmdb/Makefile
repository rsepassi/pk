HDRS := $(wildcard src/*.h) $(wildcard include/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
CFLAGS += -Wno-unused-but-set-variable \
					-Wno-unused-label \
					-Wno-conversion \
					-Wno-unused-parameter

liblmdb.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

src/%.$(O): src/%.c Makefile
	$(CC) -c -Iinclude $(CFLAGS) -o $@ $<

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
