HDRS := $(wildcard include/plum/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -Iinclude/plum -D_GNU_SOURCE -DPLUM_STATIC -Wno-conversion

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
