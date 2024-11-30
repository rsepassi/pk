HDRS := $(wildcard include/ngtcp2/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -DHAVE_CONFIG_H \
								-DBUILDING_NGTCP2 \
								-DNGTCP2_STATICLIB \
								-fvisibility=hidden \
								-isystem src

include $(ROOTDIR)/scripts/bdir.mk
$(BDIR)/.build: $(BDIR)/libngtcp2.a $(wildcard *.pc)
	[ $(TARGET_OS) != "windows" ] || cp ngtcp2.windows.pc $(BDIR)/ngtcp2.pc
	touch $@


include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
