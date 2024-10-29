libunity.a: src/unity.c
	$(CC) $(CFLAGS) -Iinclude -c $<
	$(AR) rcs $@ unity.o
	touch .build

clean:
	rm -f *.a *.o .build
