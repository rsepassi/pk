zig-out/lib/libuv.a:
	zig build -Doptimize=$(ZIG_OPT) -Dtarget=$(TARGET)
	touch .build

clean:
	rm -rf .zig-cache zig-out .build
