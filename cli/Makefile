include $(ROOTDIR)/scripts/bdir.mk

DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

LOCAL_CFLAGS += -Wno-unused-parameter

BIN := cli

.PHONY: default
default: $(BDIR)/bin/$(BIN)$(EXE)

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/ccld.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
include $(ROOTDIR)/scripts/notest.mk
