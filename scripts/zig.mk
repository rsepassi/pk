include $(ROOTDIR)/scripts/bdir.mk

LIBNAME ?= $(notdir $(CURDIR))

ifeq ($(OPT), -O2)
ZIG_OPT := ReleaseFast
else
ZIG_OPT := Debug
endif

$(BDIR)/lib/lib$(LIBNAME).a: $(SRCS) Makefile
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET) \
		-p $(BDIR) --cache-dir $(BDIR)/zig-cache
	touch $@
	touch $(BDIR)/.build
