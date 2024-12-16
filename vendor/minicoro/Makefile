ifdef VALGRIND
LOCAL_CFLAGS += -DMCO_USE_VALGRIND
endif

ifdef CORO_VLOG
LOCAL_CFLAGS += -DMCO_VLOG_ON
endif

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
