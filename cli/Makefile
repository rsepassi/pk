DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

CFLAGS += -Wno-unused-parameter

.PHONY: default
default: build/cli$(EXE)

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
include $(ROOTDIR)/scripts/bdir.mk

build/cli$(EXE): $(OBJS) $(HDRS) Makefile $(DEPS_OK) | bdir
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) -lc
