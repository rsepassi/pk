export ROOTDIR := $(CURDIR)
export PATH := $(CURDIR)/scripts:$(PATH)

export CC := clang-17
export CCLD := zig cc
export AR := llvm-ar
export OPT := -O0

export CFLAGS += \
	$(OPT) \
	-std=c11 \
	-g3 \
	-fno-omit-frame-pointer \
	-Wall -Werror -Wextra \
	-Wconversion -Wno-sign-conversion \
	-Wno-unused-command-line-argument \
	-fPIE \
	-fstack-protector-strong -fstack-clash-protection \
	-D_FORTIFY_SOURCE=3
export LDFLAGS += \
	$(OPT) -pie -z relro -z now -z noexecstack

.PHONY: default dir clean fmt clangd
default: platform
	$(MAKE) -C cli deps
	$(MAKE) -C cli

dir: platform
	$(MAKE) -C $(DIR) deps
	$(MAKE) -C $(DIR) $(T)

clean:
	rm -rf build

fmt:
	clang-format -i `find lib cli -type f -name '*.c' -o -name '*.h'`

clangd:
	rm -rf build/clangd
	mkdir -p build/clangd
	mkclangd dirs \
		cli $(wildcard lib/*) $(wildcard vendor/*) \
		> build/clangd/compile_commands.json

LIB_DIRS := $(wildcard lib/*) $(wildcard vendor/*)
include scripts/libs.mk

TEST_DIRS := $(wildcard lib/*) vendor/base58
include scripts/tests.mk

include scripts/platform.mk
