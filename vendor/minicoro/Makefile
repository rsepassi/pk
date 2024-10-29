libminicoro.a:
	$(CC) -c $(CFLAGS) minicoro.c
	$(AR) rcs $@ minicoro.o
	touch .build

.PHONY: clean
clean:
	rm -f *.o *.a .build
