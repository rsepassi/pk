include $(ROOTDIR)/mk/bdir.mk

# Args
# * TEST_DEPS=

TEST_LIB := $(CURDIR:$(ROOTDIR)/%=%)
TEST_SRCS := $(wildcard test/*.c)
TEST_OKS := $(addprefix $(BDIR)/, $(TEST_SRCS:.c=.ok))

.PHONY: test test-clean
test: $(TEST_OKS)
test-clean:
	rm -rf $(BDIR)/test

# execute a test
# the binary disappears (??!!) so we also copy it to $<.testbin
$(BDIR)/test/%.ok: $(BDIR)/test/%$(EXE)
	cp $< $<.testbin
	$(EXEC_PREFIX) $< && touch $@

# compile a test executable
$(BDIR)/test/%$(EXE): test/%.c $(ROOTDIR)/mk/test.mk $(BDIR)/.build
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
