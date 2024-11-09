HDRS := $(wildcard src/*.h) $(wildcard include/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
CFLAGS += -Wno-unused-but-set-variable \
					-Wno-unused-label

src/%.$(O): src/%.c Makefile
	$(CC) -c -Iinclude $(CFLAGS) -o $@ $<

liblmdb.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

include $(ROOTDIR)/scripts/clean.mk
