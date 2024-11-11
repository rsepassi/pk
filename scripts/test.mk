# test/
TEST_SRCS := $(wildcard test/*.c)
TESTS := $(TEST_SRCS:.c=.ok)

TEST_CFLAGS := `need-cflags vendor/unity`
TEST_LDFLAGS := `need-libs vendor/unity`

CLEAN_ALL_EXTRAS += unity-clean

.PHONY: test
test:
	$(MAKE) $(TESTS)

.PHONY: vendor/unity
vendor/unity:
	$(MAKE) -C $(ROOTDIR)/$@

.PHONY: unity-clean
unity-clean:
	$(MAKE) -C vendor/unity clean

# compile a test executable
test/%: test/%.c vendor/unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(LDFLAGS) $(DEPS_LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS) $<

# execute a test
test/%.ok: test/%
	./$< && touch $@

.PHONY: clean-test
clean-test:
	rm -f test/*.ok
