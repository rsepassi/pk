include $(ROOTDIR)/scripts/bdir.mk

URL := http://ftp.freebsd.org/pub/FreeBSD/releases/amd64/14.2-RELEASE/base.txz
HASH := e3971a3d4f36ed1ac67d2e7a5501726de79dd3695aa76bfad2a4ebe91a88a134
BSD_SRC_TAR := $(BCACHE)/content/$(HASH)
SRC := $(BDIR)/freebsd/COPYRIGHT

$(BDIR)/.build: $(SRC)

$(SRC): $(BSD_SRC_TAR)
	mkdir -p $(BDIR)/freebsd
	tar mxf $(BSD_SRC_TAR) -C $(BDIR)/freebsd --strip-components=1 \
		usr/lib usr/include lib

$(BSD_SRC_TAR):
	fetch $(URL) $(HASH)
