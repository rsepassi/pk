DEPS := lib/cbase vendor/minicoro
TEST_DEPS := lib/uvco

ifdef CORO_VLOG
LOCAL_CFLAGS += -DCOCO_VLOG=1
endif

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
include $(ROOTDIR)/mk/test.mk
