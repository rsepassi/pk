libargparse.a: src/argparse.c | Makefile
	$(CC) -c $(CFLAGS) -Iinclude src/argparse.c
	$(AR) rcs $@ argparse.$(O)
	touch .build

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
