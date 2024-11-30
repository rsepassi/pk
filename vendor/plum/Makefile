HDRS := $(wildcard include/plum/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -Iinclude/plum -D_GNU_SOURCE -DPLUM_STATIC -Wno-conversion

.PHONY: disabled
disabled:
	mkdir -p $(BDIR)
	cp disabled.pc $(BDIR)/plum.pc
	touch $(BDIR)/.build

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
