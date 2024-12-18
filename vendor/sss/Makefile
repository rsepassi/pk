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

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
include $(ROOTDIR)/scripts/test.mk
