#SRCS := $(shell find . -type f -name '*.c' -o -name '*.h')

LOCAL_CFLAGS := \
	-Isrc \
	-std=gnu89 \
	-DPACKAGE_NAME="libuv" \
	-DPACKAGE_TARNAME="libuv" \
	-DPACKAGE_VERSION="1.49.2" \
	-DPACKAGE_STRING="libuv 1.49.2" \
	-DPACKAGE_BUGREPORT="https://github.com/libuv/libuv/issues" \
	-DPACKAGE_URL="" \
	-DPACKAGE="libuv" \
	-DVERSION="1.49.2" \
	-DSUPPORT_ATTRIBUTE_VISIBILITY_DEFAULT=1 \
	-DSUPPORT_FLAG_VISIBILITY=1 \
	-DHAVE_STDIO_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_INTTYPES_H=1 \
	-DHAVE_STDINT_H=1 \
	-DHAVE_STRINGS_H=1 \
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DSTDC_HEADERS=1 \
	-Wno-shorten-64-to-32 \
	-Wno-conversion \
	-Wno-unused-parameter \
	-Wno-sign-compare

SRCS := $(wildcard src/*.c)
UNIX_SRCS := \
	src/unix/async.c \
	src/unix/core.c \
	src/unix/dl.c \
	src/unix/fs.c \
	src/unix/getaddrinfo.c \
	src/unix/getnameinfo.c \
	src/unix/loop-watcher.c \
	src/unix/loop.c \
	src/unix/pipe.c \
	src/unix/poll.c \
	src/unix/process.c \
	src/unix/random-devurandom.c \
	src/unix/signal.c \
	src/unix/stream.c \
	src/unix/tcp.c \
	src/unix/thread.c \
	src/unix/tty.c \
	src/unix/udp.c

ifeq ($(TARGET_OS), windows)
	SRCS += $(wildcard src/win/*.c)
	LOCAL_CFLAGS += \
    -DWIN32_LEAN_AND_MEAN \
    -D_FILE_OFFSET_BITS=64
else ifeq ($(TARGET_OS), macos)
	SRCS += \
		$(UNIX_SRCS) \
    src/unix/bsd-ifaddrs.c \
    src/unix/darwin-proctitle.c \
    src/unix/darwin.c \
    src/unix/fsevents.c \
    src/unix/kqueue.c \
    src/unix/proctitle.c \
    src/unix/random-getentropy.c
	LOCAL_CFLAGS += \
    -mmacosx-version-min=13.0 \
    -D_DARWIN_USE_64_BIT_INODE=1 \
    -D_DARWIN_UNLIMITED_SELECT=1 \
    -DHAVE_DLFCN_H=1 \
    -DHAVE_PTHREAD_PRIO_INHERIT=1
else ifeq ($(TARGET_OS), linux)
	SRCS += \
		$(UNIX_SRCS) \
    src/unix/linux.c \
    src/unix/procfs-exepath.c \
    src/unix/proctitle.c \
    src/unix/random-getrandom.c \
    src/unix/random-sysctl-linux.c
	LOCAL_CFLAGS += \
    -D_GNU_SOURCE \
    -DHAVE_DLFCN_H=1 \
    -DHAVE_PTHREAD_PRIO_INHERIT=1
else ifeq ($(TARGET_OS), freebsd)
	SRCS += \
		$(UNIX_SRCS) \
    src/unix/bsd-ifaddrs.c \
    src/unix/bsd-proctitle.c \
    src/unix/freebsd.c \
    src/unix/kqueue.c \
    src/unix/posix-hrtime.c \
    src/unix/random-getrandom.c
	LOCAL_CFLAGS += \
    -D_GNU_SOURCE \
    -DHAVE_DLFCN_H=1 \
    -DHAVE_PTHREAD_PRIO_INHERIT=1
endif

include $(ROOTDIR)/scripts/cc.mk
include $(ROOTDIR)/scripts/nodeps.mk
include $(ROOTDIR)/scripts/clean.mk
