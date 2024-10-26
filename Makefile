export CC := zig cc
export PATH := scripts:$(PATH)

CFLAGS += -std=c99 -Wall -Werror -DDEBUG

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

# vendor/
DEPS := libsodium libuv arena minicoro
DEPS_CFLAGS := \
		`need-cflags vendor/libsodium sodium` \
		`need-cflags vendor/minicoro` \
		`need-cflags vendor/libuv uv`
DEPS_LDFLAGS := \
		`need-libs vendor/libsodium sodium` \
		`need-libs vendor/minicoro` \
		`need-libs vendor/libuv uv`

BUILD_DEPS := $(HDRS) Makefile build/.mk

# compile the client executable
build/client: $(OBJS) $(BUILD_DEPS) deps
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
build/test/%: test/%.c $(BUILD_DEPS) deps unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(DEPS_LDFLAGS) $(TEST_FLAGS) $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	$(MAKE) -C vendor/$@

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

.PHONY: clean-all
clean-all:
	$(MAKE) clean
	$(MAKE) -C vendor/libsodium clean
	$(MAKE) -C vendor/libuv clean
	$(MAKE) -C vendor/arena clean
	$(MAKE) -C vendor/minicoro clean
	$(MAKE) -C vendor/unity clean
