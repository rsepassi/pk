include $(ROOTDIR)/mk/bdir.mk

URL := https://github.com/mstorsjo/llvm-mingw/releases/download/20241119/llvm-mingw-20241119-ucrt-ubuntu-20.04-x86_64.tar.xz
HASH := 5b2173bf32cd9ba06d2f8ee8ad5268adffe7e53cbf35f5a5ccff3e1b3869b468
MINGW_SRC_TAR := $(BCACHE)/content/$(HASH)
SRC := $(BDIR)/mingw/LICENSE.TXT
PROCESSED := $(BDIR)/mingw/x86_64-w64-mingw32/lib/libc.a

$(BDIR)/.build: $(PROCESSED) $(wildcard *.pc)
	cp windows.$(TARGET_ARCH).pc $(BDIR)/windows.pc
	touch $(BDIR)/.build

$(PROCESSED): $(SRC)
	ln -s \
		$(BDIR)/mingw/x86_64-w64-mingw32/lib/libmingw32.a \
		$(BDIR)/mingw/x86_64-w64-mingw32/lib/libc.a
	ln -s \
		$(BDIR)/mingw/aarch64-w64-mingw32/lib/libmingw32.a \
		$(BDIR)/mingw/aarch64-w64-mingw32/lib/libc.a

$(SRC): $(MINGW_SRC_TAR)
	mkdir -p $(BDIR)/mingw
	tar mxf $(MINGW_SRC_TAR) -C $(BDIR)/mingw --strip-components=1

$(MINGW_SRC_TAR):
	fetch $(URL) $(HASH)
