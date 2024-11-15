HDRS := $(wildcard src/*.h)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

DEPS_PATHS := $(wildcard $(ROOTDIR)/lib/*) \
							$(wildcard $(ROOTDIR)/vendor/*)
DEPS := $(DEPS_PATHS:$(ROOTDIR)/%=%)

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
