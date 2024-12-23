include $(ROOTDIR)/mk/bdir.mk

SRCS := $(wildcard src/*.c) $(wildcard src/lib/*.c)
HDRS := $(wildcard src/*.h) $(wildcard src/lib/*.h)
BIN := make

LOCAL_CFLAGS += \
	-DHAVE_CONFIG_H \
	-DLIBDIR=\"\" \
	-DLOCALEDIR=\"\" \
	-DINCLUDEDIR=\"\" \
	-Isrc -Isrc/lib \
	-Wno-unused-parameter \
	-Wno-shorten-64-to-32 \
	-Wno-deprecated-non-prototype \
	-Wno-implicit-int-float-conversion \
	-Wno-return-type \
	-Wno-unused-but-set-variable \
	-Wno-string-compare

.PHONY: default
default: make

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/ccld.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
