include $(ROOTDIR)/scripts/bdir.mk

DEPS := lib/cbase vendor/uv vendor/picoquic
DEMO := $(BDIR)/bin/demo$(EXE)

.PHONY: default
default: $(DEMO)

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk

$(DEMO): $(OBJS) $(HDRS) Makefile $(DEPS_OK)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) -lc
