include $(ROOTDIR)/mk/bdir.mk

DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

LOCAL_CFLAGS += -Wno-unused-parameter

BIN := cli

ifdef CORO_VLOG
	LOCAL_CFLAGS += -DCORO_VLOG=1
endif

.PHONY: default
default: cli

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/ccld.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
include $(ROOTDIR)/mk/notest.mk
