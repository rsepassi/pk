# test/
TEST_SRCS := $(wildcard test/*.c)
TESTS := $(TEST_SRCS:.c=.ok)

TEST_CFLAGS := `need --cflags vendor/unity`
TEST_LDFLAGS := `need --libs vendor/unity`

CLEAN_ALL_EXTRAS += unity-clean clean-test

.PHONY: test
test:
	$(MAKE) $(TESTS)

# compile a test executable
test/%: test/%.c vendor/unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(LDFLAGS) $(DEPS_LDFLAGS) $(TEST_CFLAGS) $(TEST_LDFLAGS) $<

# execute a test
test/%.ok: test/%
	./$< && touch $@

.PHONY: unity-build unity-clean clean-test
unity-build:
	$(MAKE) -C $(ROOTDIR)/$@

unity-clean:
	$(MAKE) -C vendor/unity clean

clean-test:
	rm -f test/*.ok
