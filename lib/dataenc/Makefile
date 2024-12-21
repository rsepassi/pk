include $(ROOTDIR)/mk/bdir.mk

HDRS := \
	$(wildcard include/*.h) \
	$(BDIR)/include/dataenc_parse_tokens.h
SRCS := \
	$(wildcard src/*.c) \
	$(BDIR)/dataenc_parse.c

DEPS := lib/cbase
TOOL_DEPS := vendor/lemon

LOCAL_CFLAGS += \
	-I$(BDIR)/include \
	-Isrc \
	-Wno-unused-parameter -Wno-unused-variable

LEMON := $(BROOT_HOST)/vendor/lemon/bin/lemon

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/test.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk

# Parser generator
$(BDIR)/include/dataenc_parse_tokens.h: $(BDIR)/dataenc_parse.out
	mkdir -p $(BDIR)/include
	cp $(BDIR)/dataenc_parse.h $@
$(BDIR)/dataenc_parse.c: $(BDIR)/dataenc_parse.out
	touch $@
$(BDIR)/dataenc_parse.out: src/dataenc_parse.y src/dataenc_parse.inc
	$(LEMON) $< -d$(BDIR) -T$(ROOTDIR)/vendor/lemon/src/lempar.c
