include $(ROOTDIR)/mk/bdir.mk

# Args
LIBNAME ?= $(notdir $(CURDIR))
HDRS ?= $(wildcard include/*.h) $(wildcard src/*.h)
SRCS ?= $(wildcard src/*.c)

OBJS := $(SRCS:.c=.$(O))
OBJS := $(OBJS:.S=.$(O))
OBJS := $(addprefix $(BDIR)/, $(OBJS))
LIB := $(BDIR)/lib$(LIBNAME).a
CLANGDS := $(SRCS:.c=.clangd)

ifdef DEPS
DEPS_OK := $(BDIR)/.deps.ok
endif

MK_DEPS := \
	$(HDRS) \
	$(DEPS_OK) \
	Makefile \
	$(ROOTDIR)/mk/cc.mk
CC_CFLAGS := -Iinclude $(CFLAGS) `need --cflags $(DEPS)` $(LOCAL_CFLAGS)

.PHONY: lib
lib: $(LIB)

$(LIB): $(OBJS) $(SRCS) $(MK_DEPS)
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
