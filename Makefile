include scripts/platform.mk

export ROOTDIR := $(CURDIR)
export PATH := $(CURDIR)/scripts:$(PATH)

export CC := zig cc
export AR := zig ar
export OPT := -O0
export ZIG_OPT := Debug

export CFLAGS += \
	$(OPT) \
	-target $(TARGET) \
	-std=c11 \
	-g3 \
	-Wall -Werror -Wextra \
	-Wdouble-promotion -Wconversion -Wno-sign-conversion
export LDFLAGS += $(OPT) -target $(TARGET)

DEPS_PATHS := $(dir $(shell find cli lib vendor -type f -name Makefile))
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

.PHONY: default dir clean fmt cli clangd
default: cli

dir:
	$(MAKE) -C $(DIR) deps
	$(MAKE) -C $(DIR) $(T)

clean:
	rm -rf build
	$(MAKE) clean-deps
	$(MAKE) clean-test
	$(MAKE) -C cli clean

fmt:
	clang-format -i `find lib cli -type f -name '*.c' -o -name '*.h'`

cli:
	$(MAKE) -C cli deps
	$(MAKE) -C cli
	ls -l build/cli/bin

clangd:
	rm -rf build/clangd
	mkdir -p build/clangd
	mkclangd dirs $(DEPS) > build/clangd/compile_commands.json

include scripts/deps.mk
include scripts/test.mk
