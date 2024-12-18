HDRS := $(wildcard include/ngtcp2/*.h) $(wildcard src/*.h)
LOCAL_CFLAGS += -DHAVE_CONFIG_H \
								-DBUILDING_NGTCP2 \
								-DNGTCP2_STATICLIB \
								-fvisibility=hidden \
								-isystem src

include $(ROOTDIR)/mk/bdir.mk
$(BDIR)/.build: $(BDIR)/libngtcp2.a $(wildcard *.pc)
	[ $(TARGET_OS) != "windows" ] || cp ngtcp2.windows.pc $(BDIR)/ngtcp2.pc
	touch $@


include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
