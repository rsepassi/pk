include $(ROOTDIR)/scripts/bdir.mk

TEST_LIB := $(CURDIR:$(ROOTDIR)/%=%)
TEST_SRCS := $(wildcard test/*.c)
TEST_OKS := $(addprefix $(BDIR)/, $(TEST_SRCS:.c=.ok))
TEST_DEPS := $(DEPS) vendor/unity

.PHONY: test test-clean
test: $(TEST_OKS)
test-clean:
	rm -rf $(BDIR)/test

# execute a test
$(BDIR)/test/%.ok: $(BDIR)/test/%$(EXE)
	cp $< $<.testbin  # the binary disappears (??!!) so copy it here
	$(EXEC_PREFIX) $< && touch $@

# compile a test executable
$(BDIR)/test/%$(EXE): test/%.c $(ROOTDIR)/scripts/test.mk $(DEPS_OK) $(BDIR)/.build
	mkdir -p $(dir $@)
	$(CCLD) -o $@.tmp $< \
		$(CFLAGS) \
		`need --cflags $(TEST_LIB)` \
		`need --cflags $(TEST_DEPS)` \
		$(LDFLAGS) \
		`need --libs $(TEST_LIB)` \
		`need --libs $(TEST_DEPS)` \
		$(PLATFORM_LDFLAGS) \
		-lc
	mv $@.tmp $@
