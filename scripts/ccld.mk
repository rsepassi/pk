include $(ROOTDIR)/scripts/bdir.mk

BINPATH := $(BDIR)/bin/$(BIN)$(EXE)

$(BINPATH): $(OBJS) $(HDRS) Makefile $(DEPS_OK)
	mkdir -p $(dir $@)
	$(CCLD) -o $@.tmp $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) $(PLATFORM_LDFLAGS) -lc
	mv $@.tmp $@
