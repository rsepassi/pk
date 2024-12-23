include $(ROOTDIR)/mk/bdir.mk

DEPS := \
	lib/allocatormi \
	lib/base64 \
	lib/bip39 \
	lib/cbase \
	lib/coco \
	lib/crypto \
	lib/dataenc \
	lib/getpass \
	lib/keyio \
	lib/nik \
	lib/signal \
	lib/tcp2 \
	lib/uvco \
	lib/xshmem \
	vendor/base58 \
	vendor/fastrange \
	vendor/lmdb \
	vendor/mimalloc \
	vendor/minicoro \
	vendor/ngtcp2 \
	vendor/optparse \
	vendor/plum \
	vendor/qrcodegen \
	vendor/sodium \
	vendor/sss \
	vendor/tai \
	vendor/unity \
	vendor/uv \
	vendor/vterm

LOCAL_CFLAGS += -Wno-unused-parameter

BIN := cli

ifdef CORO_VLOG
	LOCAL_CFLAGS += -DCORO_VLOG=1
endif

.PHONY: default
default: cli

include $(ROOTDIR)/mk/cc.mk
include $(ROOTDIR)/mk/ccld.mk
include $(ROOTDIR)/mk/deps.mk
include $(ROOTDIR)/mk/clean.mk
include $(ROOTDIR)/mk/notest.mk
