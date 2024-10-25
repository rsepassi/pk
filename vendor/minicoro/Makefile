libminicoro.a:
	$(CC) -c $(CFLAGS) minicoro.c
	$(AR) rcs $@ minicoro.o

.PHONY: clean
clean:
	rm -f minicoro.o libminicoro.a
