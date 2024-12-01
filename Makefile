export ROOTDIR := $(CURDIR)
export BROOT := $(ROOTDIR)/build
export PATH := $(CURDIR)/scripts:$(PATH)

export CC := zig cc
export CCLD := zig cc
export AR := zig ar
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

.PHONY: default clean fmt clangd
default: cli

clean:
	rm -rf $(BROOT)

fmt:
	clang-format -i `find lib cli -type f -name '*.c' -o -name '*.h'`

clangd: cli
	rm -rf $(BROOT)/clangd
	mkdir -p $(BROOT)/clangd
	mkclangd dirs \
		cli $(wildcard lib/*) $(wildcard vendor/*) \
		> $(BROOT)/clangd/compile_commands.json

# Subdirectory targets
ALL_LIBS := cli $(wildcard lib/*) $(wildcard vendor/*)
.PHONY: $(ALL_LIBS)
$(ALL_LIBS): platform
	$(MAKE) -C $@ deps
	$(MAKE) -C $@ $(T)

# Test targets
TEST_DIRS := $(wildcard lib/*) vendor/base58
ALL_TESTS := $(addsuffix /test, $(TEST_DIRS))
.PHONY: test $(ALL_TESTS)
test: $(ALL_TESTS)
	echo TESTS OK
test-clean:
	find $(BROOT) -type d -name 'test' | xargs rm -rf
$(ALL_TESTS): platform vendor/unity scripts/test.mk
	$(MAKE) -C $(@:%/test=%) deps
	$(MAKE) -C $(@:%/test=%) test-deps 2>/dev/null || :
	$(MAKE) -C $(@:%/test=%)
	$(MAKE) -C $(@:%/test=%) test

include scripts/platform.mk
