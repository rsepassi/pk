zig-out/lib/libsodium.a:
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET)
	touch zig-out/lib/libsodium.a
	touch .build

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
