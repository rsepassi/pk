export CC := zig cc
export AR := zig ar
export PATH := $(CURDIR)/scripts:$(PATH)
export ROOTDIR := $(CURDIR)
export OPT := -O2
export ZIG_OPT := ReleaseFast
include scripts/platform.mk
export CFLAGS += -std=c99 -nostdinc -nostdinc++ \
	-Wall -Werror \
	$(OPT) -target $(TARGET)

# src/
HDRS := $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(addprefix build/, $(notdir $(SRCS:.c=.$(O))))

# test/
TEST_SRCS := $(wildcard test/*.c)
TESTS := $(addprefix build/, $(TEST_SRCS:.c=.ok))
TEST_FLAGS := \
		`need-cflags vendor/unity` \
		`need-libs vendor/unity`

# deps lib/ vendor/
DEPS := \
		lib/getpass \
		lib/cbase \
		lib/uvco \
		vendor/libsodium \
		vendor/tai \
		vendor/libuv \
		vendor/minicoro \
		vendor/lmdb \
		vendor/base58 \
		vendor/mimalloc \
		vendor/plum \
		vendor/vterm \
		vendor/argparse

DEPS_CLEAN := $(addsuffix -clean, $(DEPS))

DEPS_CFLAGS := \
		`need-cflags lib/getpass` \
		`need-cflags lib/cbase` \
		`need-cflags lib/uvco` \
		`need-cflags vendor/libsodium sodium` \
		`need-cflags vendor/tai` \
		`need-cflags vendor/base58` \
		`need-cflags vendor/lmdb` \
		`need-cflags vendor/argparse` \
		`need-cflags vendor/minicoro` \
		`need-cflags vendor/mimalloc` \
		`need-cflags vendor/plum` \
		`need-cflags vendor/vterm` \
		`need-cflags vendor/libuv uv`
DEPS_LDFLAGS := \
		`need-libs lib/getpass` \
		`need-libs lib/cbase` \
		`need-libs lib/uvco` \
		`need-libs vendor/libsodium sodium` \
		`need-libs vendor/tai` \
		`need-libs vendor/base58` \
		`need-libs vendor/lmdb` \
		`need-libs vendor/argparse` \
		`need-libs vendor/minicoro` \
		`need-libs vendor/mimalloc` \
		`need-libs vendor/plum` \
		`need-libs vendor/vterm` \
		`need-libs vendor/libuv uv`

BUILD_DEPS = $(HDRS) Makefile build/.mk | deps

# compile the cli
build/cli$(EXE): $(OBJS) $(BUILD_DEPS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) -lc

# compile a src file
build/%.$(O): src/%.c $(BUILD_DEPS)
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

.PHONY: test
test:
	$(MAKE) $(TESTS)

# execute a test
build/test/%.ok: build/test/%
	./$< && touch $@

# compile a test executable
build/test/%: test/%.c $(BUILD_DEPS) | unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(LDFLAGS) $(DEPS_LDFLAGS) $(TEST_FLAGS) $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	$(MAKE) -C $@

.PHONY: unity
unity:
	$(MAKE) -C vendor/$@

# create the build directory
build/.mk:
	mkdir -p build/test
	touch build/.mk

.PHONY: clean
clean:
	rm -rf build

.PHONY: clean-all $(DEPS_CLEAN) unity-clean
clean-all: clean $(DEPS_CLEAN) unity-clean
$(DEPS_CLEAN):
	$(MAKE) -C $(@:-clean=) clean
unity-clean:
	$(MAKE) -C vendor/unity clean
