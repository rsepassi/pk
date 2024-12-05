include $(ROOTDIR)/scripts/bdir.mk

MUSL_SRC_URL := https://musl.libc.org/releases/musl-1.2.5.tar.gz
MUSL_SRC_HASH := a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4
MUSL_SRC_TAR := $(BCACHE)/content/$(MUSL_SRC_HASH)

# crt files extracted from Alpine 3.20 docker container
# apk add compiler-rt
# /usr/lib/llvm17/lib/clang/17/lib/linux/*

MK_ARGS := \
	prefix=$(BDIR)/sysroot/usr \
	build_prefix=$(BDIR)/build \
	ARCH=$(TARGET_ARCH) \
	CFLAGS="-target $(TARGET)"

LIBC := $(BDIR)/sysroot/usr/lib/libc.a
STDC := $(BDIR)/sysroot/usr/include/stdint.h
SRC := $(BDIR)/musl/README
CRT := $(BDIR)/compiler-rt/lib/linux/clang_rt.crtend-aarch64.o

$(BDIR)/.build: $(LIBC) $(STDC) $(CRT)
	touch $(BDIR)/.build

$(CRT): lib/clang_rt.crtend-aarch64.o
	mkdir -p $(dir $@)
	cp lib/* $(dir $@)/

$(LIBC): $(SRC) $(STDC)
	$(MAKE) -C $(BDIR)/musl $(MK_ARGS) install-libs

$(STDC): $(SRC)
	$(MAKE) -C $(BDIR)/musl $(MK_ARGS) install-headers

$(SRC): $(MUSL_SRC_TAR)
	mkdir -p $(BDIR)/musl
	tar mxf $(MUSL_SRC_TAR) -C $(BDIR)/musl --strip-components=1
	cp etc/config.mak $(BDIR)/musl/
	cp etc/Makefile $(BDIR)/musl/

$(MUSL_SRC_TAR):
	fetch $(MUSL_SRC_URL) $(MUSL_SRC_HASH)
