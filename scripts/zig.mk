LIBNAME ?= $(notdir $(CURDIR))

zig-out/lib/lib$(LIBNAME).a: $(SRCS) Makefile
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET)
	touch $@
	touch .build

