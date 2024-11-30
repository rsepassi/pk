LOCAL_CFLAGS += -Wno-unused-parameter -Wno-conversion

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk

DEPS := lib/cbase vendor/sodium
DEPS_TARGET := deps-test
include $(ROOTDIR)/scripts/deps.mk
TEST_CFLAGS := $(DEPS_CFLAGS)
TEST_LDFLAGS := $(DEPS_LDFLAGS)
include $(ROOTDIR)/scripts/test.mk
