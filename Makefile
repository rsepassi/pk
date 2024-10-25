vendor/libsodium/zig-out/lib/libsodium.a:
	cd libsodium && zig build

vendor/libuv/zig-out/lib/libuv.a:
	cd libuv && zig build

vendor/arena/libarena.a:
	make -C vendor/arena

.PHONY: clean-all
clean-all:
	rm -rf \
		libsodium/zig-* \
		libuv/zig-*
	make -C vendor/arena clean

