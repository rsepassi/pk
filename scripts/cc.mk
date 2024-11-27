include $(ROOTDIR)/scripts/bdir.mk

LIBNAME ?= $(notdir $(CURDIR))

HDRS ?= $(wildcard include/*.h) $(wildcard src/*.h)
SRCS ?= $(wildcard src/*.c)

OBJS := $(addprefix $(BDIR)/, $(SRCS:.c=.$(O)))
CLANGDS := $(SRCS:.c=.clangd)

ifdef DEPS
	DEPS_OK := $(BDIR)/.deps.ok
endif

$(BDIR)/lib$(LIBNAME).a: $(OBJS) $(SRCS) $(HDRS) $(DEPS_OK) Makefile
	$(AR) rcs $@ $(OBJS)
	touch $(BDIR)/.build

$(BDIR)/%.$(O): %.c $(HDRS) $(DEPS_OK) Makefile
	mkdir -p $(dir $@)
	$(CC) -c -o $@ -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $(LOCAL_CFLAGS) $<

.PHONY: clangds
clangds: $(CLANGDS)
%.clangd: %.c
	mkclangd file $(CURDIR) $< \
		"clang -c -o $(BDIR)/$(<:.c=.$(O)) -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $(LOCAL_CFLAGS) $<"
