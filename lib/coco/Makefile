DEPS := lib/cbase vendor/minicoro
TEST_DEPS := lib/uvco

ifdef CORO_VLOG
LOCAL_CFLAGS += -DCOCO_VLOG=1
endif

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
include $(ROOTDIR)/scripts/test.mk
