libarena.a:
	$(CC) -c $(CFLAGS) arena.c
	$(AR) rcs $@ arena.o
	touch .build

.PHONY: clean
clean:
	rm -f *.a *.o .build
