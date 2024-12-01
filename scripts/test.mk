include $(ROOTDIR)/scripts/bdir.mk

TEST_LIB := $(CURDIR:$(ROOTDIR)/%=%)
TEST_SRCS := $(wildcard test/*.c)
TEST_OKS := $(addprefix $(BDIR)/, $(TEST_SRCS:.c=.ok))

.PHONY: test test-clean
test: $(TEST_OKS)
test-clean:
	rm -rf $(BDIR)/test

# execute a test
$(BDIR)/test/%.ok: $(BDIR)/test/%$(EXE)
	$(EXEC_PREFIX) $< && touch $@

# compile a test executable
$(BDIR)/test/%$(EXE): test/%.c $(ROOTDIR)/scripts/test.mk $(DEPS_OK) $(BDIR)/.build
	mkdir -p $(dir $@)
	$(CCLD) -o $@.tmp $< \
		$(CFLAGS) \
		`need --cflags $(TEST_LIB)` \
		`need --cflags $(DEPS)` \
		`need --cflags vendor/unity` \
		$(LDFLAGS) \
		`need --libs $(TEST_LIB)` \
		`need --libs $(DEPS)` \
		`need --libs vendor/unity` \
		$(PLATFORM_LDFLAGS) \
		-lc
	mv $@.tmp $@
