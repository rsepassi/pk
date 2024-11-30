
HDRS := $(wildcard include/plum/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -Iinclude/plum -D_GNU_SOURCE -DPLUM_STATIC -Wno-conversion

include $(ROOTDIR)/scripts/bdir.mk
$(BDIR)/.build:
	mkdir -p $(BDIR)
	cp disabled.pc $(BDIR)/plum.pc
	touch $@

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
