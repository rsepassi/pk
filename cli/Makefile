include $(ROOTDIR)/scripts/bdir.mk

DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

LOCAL_CFLAGS += -Wno-unused-parameter

CLI := $(BDIR)/bin/cli$(EXE)

.PHONY: default
default: $(CLI)

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk

$(CLI): $(OBJS) $(HDRS) Makefile $(DEPS_OK)
	mkdir -p $(dir $@)
	$(CCLD) -o $@.tmp $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) $(PLATFORM_LDFLAGS) -lc
	mv $@.tmp $@
