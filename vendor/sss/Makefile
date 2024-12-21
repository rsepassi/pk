LOCAL_CFLAGS += \
	-std=c99 \
	-Wshadow \
	-Wpointer-arith \
	-Wcast-qual \
	-Wformat \
	-Wformat-security \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-fno-strict-overflow

DEPS := vendor/sodium

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/test.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
