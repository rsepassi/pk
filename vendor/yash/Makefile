include $(ROOTDIR)/mk/bdir.mk

SRCS := $(wildcard src/*.c) $(wildcard src/builtins/*.c)
HDRS := $(wildcard src/*.h) $(BDIR)/config.h $(BDIR)/signum.h
BIN := yash

LOCAL_CFLAGS += -I$(BDIR) \
								-Wno-return-type \
								-Wno-float-conversion \
								-Wno-sometimes-uninitialized \
								-Wno-implicit-int-float-conversion \
								-Wno-shorten-64-to-32 \
								-Wno-implicit-int-conversion

.PHONY: default
default: yash

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/ccld.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk

$(BDIR)/config.h: $(wildcard src/platform/*.h)
	mkdir -p $(dir $@)
	cp src/platform/config-$(TARGET_OS).h $@

$(BDIR)/signum.h: $(wildcard src/platform/*.h)
	mkdir -p $(dir $@)
	cp src/platform/signum-$(TARGET_OS).h $@
