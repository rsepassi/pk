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

# src/
HDRS := $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
DEPS := \
		lib/getpass \
		lib/cbase \
		lib/uvco \
		lib/nik \
		lib/crypto \
		vendor/sodium \
		vendor/tai \
		vendor/uv \
		vendor/minicoro \
		vendor/lmdb \
		vendor/base58 \
		vendor/mimalloc \
		vendor/plum \
		vendor/vterm \
		vendor/argparse
include $(ROOTDIR)/scripts/deps.mk

BUILD_DEPS = $(HDRS) Makefile | deps

.PHONY: cli
cli: build/cli$(EXE)

build/cli$(EXE): $(OBJS) $(SRCS) $(HDRS) $(BUILD_DEPS) build_dir
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) -lc

%.$(O): %.c $(BUILD_DEPS)
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

.PHONY: clean-all
clean-all: clean clean-deps clean-test

.PHONY: build_dir
build_dir:
	mkdir -p build

include $(ROOTDIR)/scripts/test.mk
include $(ROOTDIR)/scripts/clean.mk
