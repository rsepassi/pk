HDRS := $(wildcard src/*.h) $(wildcard include/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

src/%.o: src/%.c Makefile
	$(CC) -c -Iinclude $(CFLAGS) -Wno-unused-but-set-variable -o $@ $<

liblmdb.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

clean:
	rm -f src/*.o *.a .build
