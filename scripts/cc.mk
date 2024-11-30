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
endif
CC_DEPS = \
	$(HDRS) $(DEPS_OK) \
	Makefile \
	$(ROOTDIR)/scripts/cc.mk
CC_CFLAGS = -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $(LOCAL_CFLAGS)

$(BDIR)/lib$(LIBNAME).a: $(OBJS) $(SRCS) $(CC_DEPS)
	$(AR) rcs $@ $(OBJS)
	touch $(BDIR)/.build

$(BDIR)/%.$(O): %.c $(CC_DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $(CC_CFLAGS) $<

$(BDIR)/%.$(O): %.S $(CC_DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $(CC_CFLAGS) $<

.PHONY: clangds
clangds: $(CLANGDS)
%.clangd: %.c
	mkclangd file $(CURDIR) $< \
		"clang -c -o $(BDIR)/$(<:.c=.$(O)) $(CC_CFLAGS) $<"
