CC = zig cc
export CC

CFLAGS += -std=c99 -Wall -Werror -DDEBUG

# src/
HDRS = $(wildcard src/*.h)
SRCS = $(wildcard src/*.c)
OBJS = $(addprefix build/, $(notdir $(SRCS:.c=.o)))

# test/
TEST_SRCS = $(wildcard test/*.c)
TESTS = $(addprefix build/, $(TEST_SRCS:.c=.ok))
TEST_FLAGS = \
		`PKG_CONFIG_PATH=vendor/unity pkg-config --define-variable=prefix=vendor/unity --cflags unity` \
		`PKG_CONFIG_PATH=vendor/unity pkg-config --define-variable=prefix=vendor/unity --libs unity`

# vendor/
DEPS = libsodium libuv arena minicoro
DEPS_CFLAGS = \
		`PKG_CONFIG_PATH=vendor/libsodium pkg-config --define-variable=prefix=vendor/libsodium --cflags sodium` \
		`PKG_CONFIG_PATH=vendor/minicoro pkg-config --define-variable=prefix=vendor/minicoro --cflags minicoro` \
		`PKG_CONFIG_PATH=vendor/libuv pkg-config --define-variable=prefix=vendor/libuv --cflags uv`
DEPS_LDFLAGS = \
		`PKG_CONFIG_PATH=vendor/libsodium pkg-config --define-variable=prefix=vendor/libsodium --libs sodium` \
		`PKG_CONFIG_PATH=vendor/minicoro pkg-config --define-variable=prefix=vendor/minicoro --libs minicoro` \
		`PKG_CONFIG_PATH=vendor/libuv pkg-config --define-variable=prefix=vendor/libuv --libs uv`

BUILD_DEPS = $(HDRS) Makefile build/.mk

# compile the client executable
build/client: $(OBJS) $(BUILD_DEPS)
	$(MAKE) deps
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(DEPS_LDFLAGS) -lc

# compile a src file
build/%.o: src/%.c $(BUILD_DEPS)
	$(MAKE) deps
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

.PHONY: test
test:
	$(MAKE) $(TESTS)

# execute a test
build/test/%.ok: build/test/%
	./$< && touch $@

# compile a test executable
build/test/%: test/%.c $(BUILD_DEPS)
	$(MAKE) deps
	$(MAKE) -C vendor/unity
	$(CC) $(CFLAGS) -o $@ $(DEPS_CFLAGS) $(DEPS_LDFLAGS) $(TEST_FLAGS) $<

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
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
