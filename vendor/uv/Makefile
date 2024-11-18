SRCS := $(wildcard src/*.c) \
				$(wildcard src/*.h) \
				$(wildcard src/unix/*.c) \
				$(wildcard src/unix/*.h) \
				$(wildcard src/win/*.c) \
				$(wildcard src/win/*.h)
HDRS := $(wildcard include/*.h) $(wildcard include/uv/*.h)

zig-out/lib/libuv.a: $(SRCS) $(HDRS) Makefile
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET)
	touch zig-out/lib/libuv.a
	touch .build

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
