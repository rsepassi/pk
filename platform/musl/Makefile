include $(ROOTDIR)/scripts/bdir.mk

MK_ARGS := \
	prefix=$(BDIR)/sysroot/usr \
	build_prefix=$(BDIR)/build \
	ARCH=$(TARGET_ARCH) \
	CFLAGS="-target $(TARGET)"

$(BDIR)/sysroot/usr/lib/libc.a:
	$(MAKE) -C src $(MK_ARGS) install-libs
	$(MAKE) -C src $(MK_ARGS) install-headers
	touch $(BDIR)/.build

include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
