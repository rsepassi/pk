.PHONY: deps local-deps test-deps tool-deps
deps: local-deps tool-deps

ifdef DEPS
DEPS_OK := $(BDIR)/.deps.ok
local-deps:
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk DEPS_ARG="$(DEPS)" DEPS_OK_ARG="$(DEPS_OK)"
else
local-deps:
	@:
endif

ifdef TEST_DEPS
TEST_DEPS_OK := $(BDIR)/.testdeps.ok
test-deps:
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk DEPS_ARG="$(TEST_DEPS) vendor/unity" DEPS_OK_ARG="$(TEST_DEPS_OK)"
else
test-deps:
	@:
endif

ifdef TOOL_DEPS
TOOL_DEPS_OK := $(BDIR)/.tooldeps.ok
tool-deps:
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk DEPS_ARG="$(TOOL_DEPS)" DEPS_OK_ARG="$(TOOL_DEPS_OK)" TARGET="$(HOST)" OPT=2
else
tool-deps:
	@:
endif
