.PHONY: deps
ifdef DEPS
DEPS_OK := $(BDIR)/.deps.ok
deps:
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk DEPS_ARG="$(DEPS)"
else
deps:
	@:
endif

.PHONY: test-deps
ifdef TEST_DEPS
TEST_DEPS_OK := $(BDIR)/.testdeps.ok
test-deps:
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk DEPS_ARG="$(TEST_DEPS) vendor/unity"
else
test-deps:
	@:
endif
