HDRS := $(wildcard include/plum/*.h) $(wildcard src/*.h)
CFLAGS += -Iinclude/plum -D_GNU_SOURCE -DPLUM_STATIC -Wno-conversion

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
