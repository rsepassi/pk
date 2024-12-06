# ==============================================================================
# VARIABLES
# ==============================================================================
include scripts/target.mk
export ROOTDIR := $(CURDIR)
export BROOT_ALL := $(ROOTDIR)/build
export BROOT := $(BROOT_ALL)/$(TARGET)
export BCACHE := $(ROOTDIR)/.build-cache
export PATH := $(CURDIR)/scripts:$(PATH)

USE_CLANG ?= 1
ifeq ($(USE_CLANG), 1)
export CC := clang-17
export CCLD := clang-17
export AR := llvm-ar
else
export CC := zig cc
export CCLD := zig cc
export AR := zig ar
endif

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
	-fstack-protector-strong -fstack-clash-protection
export LDFLAGS += $(OPT)

ifeq ($(USE_CLANG), 1)
export CFLAGS += --rtlib=compiler-rt -flto
export LDFLAGS += --rtlib=compiler-rt -flto -fuse-ld=lld
endif

TEST_DIRS := $(wildcard lib/*) vendor/base58 vendor/qrcodegen
ALL_LIBS := cli $(wildcard lib/*) $(wildcard vendor/*)
ALL_TESTS := $(addsuffix /test, $(TEST_DIRS))

# ==============================================================================
# TARGETS
# ==============================================================================

.PHONY: default clean fmt clangd coverage test test-clean site service \
	$(ALL_LIBS) $(ALL_TESTS)

default: cli

clean:
	rm -rf $(BROOT)

fmt:
	clang-format -i `find lib cli -type f -name '*.c' -o -name '*.h'`

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
	ln -sf $(BROOT)/$@ $(BROOT_ALL)/out

$(ALL_TESTS): platform vendor/unity scripts/test.mk
	$(MAKE) -C $(@:%/test=%) deps
	$(MAKE) -C $(@:%/test=%) test-deps 2>/dev/null || :
	$(MAKE) -C $(@:%/test=%)
	$(MAKE) -C $(@:%/test=%) test

site:
	$(MAKE) -C site $(T)

service:
	$(MAKE) -C service $(T)

include scripts/platform.mk
