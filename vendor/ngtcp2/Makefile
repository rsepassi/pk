HDRS := $(wildcard include/ngtcp2/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -DHAVE_CONFIG_H \
								-DBUILDING_NGTCP2 \
								-DNGTCP2_STATICLIB \
								-fvisibility=hidden \
								-isystem src

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
