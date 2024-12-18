include $(ROOTDIR)/scripts/bdir.mk

ifdef DEPS
DEPS_OK := $(BDIR)/.deps.ok
endif

ifdef TEST_DEPS
TEST_DEPS_OK := $(BDIR)/.testdeps.ok
endif
