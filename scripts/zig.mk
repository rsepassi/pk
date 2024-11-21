include $(ROOTDIR)/scripts/bdir.mk

LIBNAME ?= $(notdir $(CURDIR))

$(BDIR)/lib/lib$(LIBNAME).a: $(SRCS) Makefile
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET) \
		-p $(BDIR) --cache-dir $(BDIR)/zig-cache
	touch $@
	touch $(BDIR)/.build
