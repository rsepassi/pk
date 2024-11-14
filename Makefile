export CC := zig cc
export AR := zig ar
export PATH := $(CURDIR)/scripts:$(PATH)
export ROOTDIR := $(CURDIR)
export OPT := -O2
export ZIG_OPT := ReleaseFast

include $(ROOTDIR)/scripts/platform.mk

export CFLAGS += -std=c99 -nostdinc -nostdinc++ \
	-Wall -Werror \
	$(OPT) -target $(TARGET)

DEPS := \
		lib/allocatormi \
		lib/base64 \
		lib/cbase \
		lib/crypto \
		lib/getpass \
		lib/nik \
		lib/signal \
		lib/uvco \
		vendor/argparse \
		vendor/base58 \
		vendor/fastrange \
		vendor/lmdb \
		vendor/mimalloc \
		vendor/minicoro \
		vendor/plum \
		vendor/sodium \
		vendor/tai \
		vendor/uv \
		vendor/vterm

.PHONY: cli
cli:
	$(MAKE) -C cli

.PHONY: clean-all
clean-all: clean clean-deps clean-test
	$(MAKE) -C cli clean

.PHONY: fmt
fmt:
	clang-format -i `find lib -type f -name '*.c'` `find lib -type f -name '*.h'`
	clang-format -i `find cli -type f -name '*.c'` `find cli -type f -name '*.h'`

include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/test.mk
