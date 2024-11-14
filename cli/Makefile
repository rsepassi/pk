HDRS := $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))
DEPS := \
		lib/allocatormi \
		lib/base64 \
		lib/cbase \
		lib/crypto \
		lib/getpass \
		lib/nik \
		lib/signal \
		lib/uvco \
		vendor/argparse \
		vendor/base58 \
		vendor/lmdb \
		vendor/mimalloc \
		vendor/minicoro \
		vendor/plum \
		vendor/sodium \
		vendor/tai \
		vendor/uv \
		vendor/vterm

BUILD_DEPS = $(HDRS) Makefile | deps build_dir

build/cli$(EXE): $(OBJS) $(SRCS) $(BUILD_DEPS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS) $(DEPS_LDFLAGS) -lc

%.$(O): %.c $(BUILD_DEPS)
	$(CC) -c $(CFLAGS) -o $@ $(DEPS_CFLAGS) $<

.PHONY: build_dir
build_dir:
	mkdir -p build

include $(ROOTDIR)/scripts/deps.mk
include $(ROOTDIR)/scripts/clean.mk
