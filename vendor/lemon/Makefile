# https://sqlite.org/src/doc/trunk/doc/lemon.html

SRCS := src/lemon.c
BIN := lemon
LOCAL_CFLAGS += -Wno-shorten-64-to-32 -Wno-implicit-int-conversion

.PHONY: default
default: lemon

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/ccld.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
