CC = zig cc
CFLAGS += -std=c99 -Wall -Werror -DDEBUG

HDRS = $(wildcard src/*.h)
SRCS = $(wildcard src/*.c)
OBJS = $(addprefix build/, $(notdir $(SRCS:.c=.o)))

DEPS_CFLAGS = \
		`PKG_CONFIG_PATH=vendor/libsodium pkg-config --define-variable=prefix=vendor/libsodium --cflags sodium` \
		`PKG_CONFIG_PATH=vendor/minicoro pkg-config --define-variable=prefix=vendor/minicoro --cflags minicoro` \
		`PKG_CONFIG_PATH=vendor/libuv pkg-config --define-variable=prefix=vendor/libuv --cflags uv`

DEPS_LDFLAGS = \
		`PKG_CONFIG_PATH=vendor/libsodium pkg-config --define-variable=prefix=vendor/libsodium --libs sodium` \
		`PKG_CONFIG_PATH=vendor/minicoro pkg-config --define-variable=prefix=vendor/minicoro --libs minicoro` \
		`PKG_CONFIG_PATH=vendor/libuv pkg-config --define-variable=prefix=vendor/libuv --libs uv`

build/client: $(OBJS) build/.mk
	make deps
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(DEPS_LDFLAGS) -lc

build/%.o: src/%.c $(HDRS) Makefile
	make deps
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

build/.mk:
	mkdir -p build
	touch build/.mk

.PHONY: deps
deps:
	make -C vendor/libsodium
	make -C vendor/libuv
	make -C vendor/arena
	make -C vendor/minicoro

.PHONY: clean
clean:
	rm -rf build

.PHONY: clean-all
clean-all:
	make clean
	make -C vendor/libsodium clean
	make -C vendor/libuv clean
	make -C vendor/arena clean
	make -C vendor/minicoro clean
