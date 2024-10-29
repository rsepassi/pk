libargparse.a: src/argparse.c | Makefile
	$(CC) -c $(CFLAGS) -Iinclude src/argparse.c
	$(AR) rcs $@ argparse.o
	touch .build

clean:
	rm -f *.o *.a .build
