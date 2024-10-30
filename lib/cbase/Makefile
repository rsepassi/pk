HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

libcbase.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.o: %.c
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

clean:
	rm -f *.a src/*.o .build
