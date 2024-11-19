export CC := zig cc
export AR := zig ar
export PATH := $(CURDIR)/scripts:$(PATH)
export ROOTDIR := $(CURDIR)
export OPT := -O2
export ZIG_OPT := ReleaseFast

include $(ROOTDIR)/scripts/platform.mk

export CFLAGS += -std=c11 -nostdinc -nostdinc++ -g3 \
	-Wall -Werror -Wextra \
	-Wdouble-promotion -Wconversion -Wno-sign-conversion \
	$(OPT) -target $(TARGET)

DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

.PHONY: cli clean-all fmt dir
cli:
	$(MAKE) -C cli deps
	$(MAKE) -C cli

clean-all: clean-deps clean-test
	$(MAKE) -C cli clean

fmt:
	clang-format -i `find lib -type f -name '*.c'` `find lib -type f -name '*.h'`
	clang-format -i `find cli -type f -name '*.c'` `find cli -type f -name '*.h'`

dir:
	$(MAKE) -C $(DIR) deps
	$(MAKE) -C $(DIR) $(DIRTARGET)

include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/test.mk
