include $(ROOTDIR)/scripts/bdir.mk

LIBNAME ?= $(notdir $(CURDIR))

HDRS ?= $(wildcard include/*.h) $(wildcard src/*.h)
SRCS ?= $(wildcard src/*.c)

OBJS := $(SRCS:.c=.$(O))
OBJS := $(OBJS:.S=.$(O))
OBJS := $(addprefix $(BDIR)/, $(OBJS))
CLANGDS := $(SRCS:.c=.clangd)

ifdef DEPS
	DEPS_OK := $(BDIR)/.deps.ok
	CC_DEPS := $(DEPS)
endif
MK_DEPS := \
	$(HDRS) $(DEPS_OK) \
	Makefile \
	$(ROOTDIR)/scripts/cc.mk
CC_CFLAGS = -Iinclude $(CFLAGS) `need --cflags $(CC_DEPS)` $(LOCAL_CFLAGS)

$(BDIR)/lib$(LIBNAME).a: $(OBJS) $(SRCS) $(MK_DEPS)
	$(AR) rcs $@ $(OBJS)
	touch $(BDIR)/.build

$(BDIR)/%.$(O): %.c $(MK_DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $(CC_CFLAGS) $<

$(BDIR)/%.$(O): %.S $(MK_DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $(CC_CFLAGS) $<

.PHONY: clangds
clangds: $(CLANGDS)
%.clangd: %.c
	mkclangd file $(CURDIR) $< \
		"clang -c -o $(BDIR)/$(<:.c=.$(O)) $(CC_CFLAGS) $<"
