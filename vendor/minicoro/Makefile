libminicoro.a: minicoro.c minicoro.h Makefile
	$(CC) -c $(CFLAGS) minicoro.c -o minicoro.$(O)
	$(AR) rcs $@ minicoro.$(O)
	touch .build

include $(ROOTDIR)/scripts/clean.mk
