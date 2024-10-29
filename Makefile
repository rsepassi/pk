export CC := zig cc
export AR := zig ar
export PATH := $(CURDIR)/scripts:$(PATH)
export ROOTDIR := $(CURDIR)
export CFLAGS += -std=c99 -Wall -Werror -O2

# src/
HDRS := $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(addprefix build/, $(notdir $(SRCS:.c=.o)))

# test/
TEST_SRCS := $(wildcard test/*.c)
TESTS := $(addprefix build/, $(TEST_SRCS:.c=.ok))
TEST_FLAGS := \
		`need-cflags vendor/unity` \
		`need-libs vendor/unity`

# lib/ vendor/
LIB_DEPS := getpass cbase uvco
VENDOR_DEPS := libsodium libuv arena minicoro lmdb argparse
DEPS := $(LIB_DEPS) $(VENDOR_DEPS)

LIB_DEPS_CLEAN := $(addsuffix -clean, $(LIB_DEPS))
VENDOR_DEPS_CLEAN := $(addsuffix -clean, $(VENDOR_DEPS))
DEPS_CLEAN := $(LIB_DEPS_CLEAN) $(VENDOR_DEPS_CLEAN)

LIB_DEP_FILES := $(addprefix lib/, $(addsuffix /.build, $(LIB_DEPS)))
VENDOR_DEP_FILES := $(addprefix vendor/, $(addsuffix /.build, $(VENDOR_DEPS)))
DEP_FILES := $(LIB_DEP_FILES) $(VENDOR_DEP_FILES)

DEPS_CFLAGS := \
		`need-cflags lib/getpass` \
		`need-cflags lib/cbase` \
		`need-cflags lib/uvco` \
		`need-cflags vendor/libsodium sodium` \
		`need-cflags vendor/lmdb` \
		`need-cflags vendor/argparse` \
		`need-cflags vendor/minicoro` \
		`need-cflags vendor/libuv uv`
DEPS_LDFLAGS := \
		`need-libs lib/getpass` \
		`need-libs lib/cbase` \
		`need-libs lib/uvco` \
		`need-libs vendor/libsodium sodium` \
		`need-libs vendor/lmdb` \
		`need-libs vendor/argparse` \
		`need-libs vendor/minicoro` \
		`need-libs vendor/libuv uv`

BUILD_DEPS = $(HDRS) Makefile build/.mk $(DEP_FILES)

# compile the client executable
build/client: $(OBJS) $(BUILD_DEPS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(DEPS_LDFLAGS) -lc

# compile a src file
build/%.o: src/%.c $(BUILD_DEPS)
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

.PHONY: test
test:
	$(MAKE) $(TESTS)

# execute a test
build/test/%.ok: build/test/%
	./$< && touch $@

# compile a test executable
build/test/%: test/%.c $(BUILD_DEPS) | unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(DEPS_LDFLAGS) $(TEST_FLAGS) $<

$(LIB_DEPS):
	$(MAKE) -C lib/$@
$(VENDOR_DEPS):
	$(MAKE) -C vendor/$@
$(LIB_DEP_FILES): $(LIB_DEPS)
$(VENDOR_DEP_FILES): $(VENDOR_DEPS)

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

.PHONY: clean-all $(DEPS_CLEAN)
clean-all: clean $(DEPS_CLEAN)
$(LIB_DEPS_CLEAN):
	$(MAKE) -C lib/$(@:-clean=) clean
$(VENDOR_DEPS_CLEAN):
	$(MAKE) -C vendor/$(@:-clean=) clean
