HDRS := $(wildcard include/*.h) $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

libbase58.a: $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -Iinclude -o $@ $<

clean:
	rm -f *.a src/*.o .build
