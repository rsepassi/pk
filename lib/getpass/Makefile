libgetpass.a: src/getpass.c include/getpass.h
	$(CC) -c $(CFLAGS) -Iinclude $<
	$(AR) rcs $@ getpass.$(O)
	touch .build

include $(ROOTDIR)/scripts/clean.mk
