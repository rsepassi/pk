libunity.a: src/unity.c
	$(CC) $(CFLAGS) -Iinclude -c $<
	$(AR) rcs $@ unity.$(O)
	touch .build

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
