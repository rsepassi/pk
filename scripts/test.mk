include $(ROOTDIR)/scripts/bdir.mk

TEST_LIB := $(CURDIR:$(ROOTDIR)/%=%)
TEST_SRCS := $(wildcard test/*.c)
TEST_OKS := $(addprefix $(BDIR)/, $(TEST_SRCS:.c=.ok))
TEST_DEPS := $(ROOTDIR)/scripts/test.mk $(BDIR)/.build

.PHONY: test
test: $(TEST_OKS)

# execute a test
$(BDIR)/test/%.ok: $(BDIR)/test/%$(EXE)
	$< && touch $@

# compile a test executable
$(BDIR)/test/%$(EXE): test/%.c $(TEST_DEPS)
	mkdir -p $(dir $@)
	$(CC) -o $@.tmp $< \
		$(CFLAGS) \
		`need --cflags $(TEST_LIB)` \
		`need --cflags vendor/unity` \
		$(LDFLAGS) \
		`need --libs $(TEST_LIB)` \
		`need --libs vendor/unity` \
		$(PLATFORM_LDFLAGS) \
		-lc
	mv $@.tmp $@
