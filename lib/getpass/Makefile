libgetpass.a: src/getpass.c include/getpass.h
	$(CC) -c $(CFLAGS) -Iinclude $<
	$(AR) rcs $@ getpass.o
	touch .build

clean:
	rm -f *.a *.o .build
