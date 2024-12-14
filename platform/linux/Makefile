include $(ROOTDIR)/scripts/bdir.mk

MUSL_SRC_URL := https://musl.libc.org/releases/musl-1.2.5.tar.gz
MUSL_SRC_HASH := a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4
MUSL_SRC_TAR := $(BCACHE)/content/$(MUSL_SRC_HASH)

.PHONY: build apks clangds
build: $(BDIR)/.build
clangds:

MK_ARGS := \
	prefix=$(BDIR)/sysroot/usr \
	build_prefix=$(BDIR)/build \
	ARCH=$(TARGET_ARCH) \
	CFLAGS="-target $(TARGET)"

LIBC := $(BDIR)/sysroot/usr/lib/libc.a
STDC := $(BDIR)/sysroot/usr/include/stdint.h
SRC := $(BDIR)/musl/README
CRT := $(BDIR)/compiler-rt/lib/linux/clang_rt.crtend-aarch64.o
PKGS := $(BDIR)/linux_alpine/.build

$(BDIR)/.build: $(LIBC) $(STDC) $(CRT) $(PKGS) Makefile
	ln -sf $(LIBC) $(BDIR)/sysroot/usr/lib/libssp_nonshared.a
	ln -sf $(LIBC) $(BDIR)/sysroot/usr/lib/libpthread.a
	ln -sf $(LIBC) $(BDIR)/sysroot/usr/lib/librt.a
	ln -sf $(LIBC) $(BDIR)/sysroot/usr/lib/libm.a
	ln -sf $(LIBC) $(BDIR)/sysroot/usr/lib/libdl.a
	touch $(BDIR)/.build

$(CRT): lib/clang_rt.crtend-aarch64.o
	mkdir -p $(dir $@)
	cp lib/* $(dir $@)/

$(LIBC): $(SRC) $(STDC)
	$(MAKE) -C $(BDIR)/musl $(MK_ARGS) install-libs

$(STDC): $(SRC)
	$(MAKE) -C $(BDIR)/musl $(MK_ARGS) install-headers

$(SRC): $(MUSL_SRC_TAR) etc/Makefile etc/config.mak
	mkdir -p $(BDIR)/musl
	tar mxf $(MUSL_SRC_TAR) -C $(BDIR)/musl --strip-components=1
	cp etc/config.mak $(BDIR)/musl/
	cp etc/Makefile $(BDIR)/musl/

$(MUSL_SRC_TAR):
	fetch $(MUSL_SRC_URL) $(MUSL_SRC_HASH)

$(PKGS): $(BCACHE)/linux_alpine/$(TARGET_ARCH)/.build Makefile
	mkdir -p $(dir $@)/usr/include $(dir $@)/usr/lib $(dir $@)/compiler-rt/lib
	cp -r $(dir $<)/usr/include/linux $(dir $@)/usr/include/
	cp -r $(dir $<)/usr/include/asm $(dir $@)/usr/include/
	cp -r $(dir $<)/usr/include/asm-generic $(dir $@)/usr/include/
	cp -r $(dir $<)/usr/lib/llvm17/lib/clang/17/lib/linux $(dir $@)/compiler-rt/lib/
	cp -r $(dir $<)/usr/lib/libunwind.a $(dir $@)/usr/lib
	touch $@

apks: $(BCACHE)/linux_alpine/$(TARGET_ARCH)/.build

ifeq ($(HOST_OS), macos)

$(BCACHE)/linux_alpine/$(TARGET_ARCH)/.build: xdeps pkgs.txt

.PHONY: xdeps
xdeps:
	podman build -q -f $(ROOTDIR)/scripts/build.containerfile -t pkbuild > /dev/null
	podman run -v $(ROOTDIR):/root/pk pkbuild make --silent platform T=apks

else

$(BCACHE)/linux_alpine/$(TARGET_ARCH)/.build: scripts/apk pkgs.txt
	./scripts/apk `cat pkgs.txt`
	touch $@

endif
