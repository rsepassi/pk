CFLAGS += -DPTLS_WITHOUT_OPENSSL \
					-DPTLS_WITHOUT_FUSION \
					-DPICOQUIC_WITHOUT_SSLKEYLOG \
					-Wno-unused-parameter \
					-Wno-conversion \
					-Wno-sign-compare \
					-Wno-ignored-qualifiers \
					-D_GNU_SOURCE

DEPS := vendor/sodium

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
