include $(ROOTDIR)/scripts/bdir.mk

BINPATH ?= $(BDIR)/bin/$(BIN)$(EXE)

.PHONY: $(BIN)
$(BIN): $(BINPATH)

$(BINPATH): $(OBJS) $(HDRS) Makefile $(DEPS_OK)
	mkdir -p $(dir $@)
	$(CCLD) -o $@.tmp \
		$(OBJS) \
		$(LDFLAGS) \
		`need --libs $(DEPS)` \
		$(PLATFORM_LDFLAGS) \
		-lc
	mv $@.tmp $@
