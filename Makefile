# ==============================================================================
# VARIABLES
# ==============================================================================
include mk/target.mk

export \
	TARGET TARGET_OS TARGET_ARCH HOST HOST_OS HOST_ARCH \
	ROOTDIR BROOT_ALL BROOT BROOT_HOST BCACHE PATH ROOTTIME \
	SHELL CC CCLD AR CFLAGS LDFLAGS OPT \
	O EXE VALGRIND ASAN MSAN EXEC_PREFIX PLATFORM_LDFLAGS

ROOTDIR := $(CURDIR)
BROOT_ALL := $(ROOTDIR)/build
BROOT := $(BROOT_ALL)/$(TARGET)
BROOT_HOST := $(BROOT_ALL)/$(HOST)
BCACHE := $(ROOTDIR)/.build-cache
PATH := $(CURDIR)/scripts:$(PATH)
ROOTTIME := $(shell date +%s)
SHELL := $(BROOT_HOST)/vendor/yash/bin/yash

USE_CLANG := 1
ifeq ($(USE_CLANG), 1)
CC := clang-19
CCLD := clang-19
AR := llvm-ar
else
CC := zig cc
CCLD := zig cc
AR := zig ar
endif

OPT := 0

CFLAGS += \
	-O$(OPT) \
	-std=c11 \
	-g3 \
	-fno-omit-frame-pointer \
	-Wall -Werror -Wextra \
	-Wconversion -Wno-sign-conversion \
	-Wno-unused-command-line-argument \
	-fPIE
LDFLAGS += -O$(OPT) -fuse-ld=lld

ifeq ($(USE_CLANG), 1)
CFLAGS += --rtlib=compiler-rt
LDFLAGS += --rtlib=compiler-rt
endif

ifneq ($(OPT), 0)
CFLAGS += \
	-flto \
	-fstack-protector-strong -fstack-clash-protection
LDFLAGS += -flto
endif

TEST_DIRS := $(wildcard lib/*) vendor/base58 vendor/qrcodegen vendor/sss
ALL_LIBS := cli $(wildcard lib/*) $(wildcard vendor/*)
ALL_LIBS_NOLINK := $(addsuffix .nolink, $(ALL_LIBS))
ALL_TESTS := $(addsuffix /test, $(TEST_DIRS))
ALL_PLATFORMS := $(wildcard platform/*)

# ==============================================================================
# TARGETS
# ==============================================================================

.PHONY: default clean fmt clangd coverage test test-clean site service \
	$(ALL_LIBS) $(ALL_LIBS_NOLINK) $(ALL_TESTS) $(ALL_PLATFORMS)

default: cli

clean:
	rm -rf $(BROOT)

fmt:
	clang-format -i `find lib cli -type f -name '*.c' -o -name '*.inc' -o -name '*.h'`

clangd: $(ALL_LIBS)
	mkdir -p $(BROOT)/clangd
	mkclangd dirs $(ALL_LIBS) > $(BROOT)/clangd/compile_commands.json

coverage:
	coverage $(BIN) $(SRC)

# Test targets
test: $(ALL_TESTS)
	echo TESTS OK
test-clean:
	find $(BROOT) -type d -name 'test' | xargs rm -rf

$(ALL_LIBS): platform
	$(MAKE) -C $@ deps
	$(MAKE) -C $@ $(T)
	rm -f $(BROOT_ALL)/out
	if [ -d $(BROOT)/$@ ]; then ln -s $(BROOT)/$@ $(BROOT_ALL)/out; fi

$(ALL_LIBS_NOLINK): platform
	$(MAKE) -C $(@:%.nolink=%) deps
	$(MAKE) -C $(@:%.nolink=%) $(T)

$(ALL_TESTS): platform
	$(MAKE) -C $(@:%/test=%) deps
	$(MAKE) -C $(@:%/test=%)
	$(MAKE) -C $(@:%/test=%) test

$(ALL_PLATFORMS):
	$(MAKE) -C $@ $(T)

site:
	$(MAKE) -C site $(T)

service:
	$(MAKE) -C service $(T)

include mk/platform.mk
