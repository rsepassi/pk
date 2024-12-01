# Cross-platform support

# uname target detection
ifndef TARGET
	OS := $(shell uname)
	ARCH := $(shell uname -m)
	ifeq ($(OS), Darwin)
		ifeq ($(ARCH), arm64)
			export TARGET := aarch64-macos
		else
			export TARGET := x86_64-macos
		endif
	else
		ifeq ($(ARCH), arm64)
			export TARGET := aarch64-linux-musl
		else
			export TARGET := x86_64-linux-musl
		endif
	endif
else
export TARGET
endif

export TARGET_ARCH := $(word 1, $(subst -, ,$(TARGET)))
export TARGET_OS   := $(word 2, $(subst -, ,$(TARGET)))

# object/executable suffixes
ifeq ($(TARGET_OS), windows)
export O := obj
export EXE := .exe
else
export O := o
export EXE :=
endif

# valgrind
ifdef VALGRIND
export VALGRIND := 1
export EXEC_PREFIX := valgrind -s --leak-check=full --show-leak-kinds=all \
	--track-origins=yes --num-callers=16
export CFLAGS += -isystem $(CURDIR)/platform/valgrind/include
endif

.PHONY: platform

ifeq ($(TARGET_OS), macos)

export CFLAGS += \
	-target $(TARGET_ARCH)-apple-macosx13 \
	$(shell need --cflags platform/macos)
export PLATFORM_LDFLAGS += \
	-target $(TARGET) \
	$(shell need --libs platform/macos)

platform:
	$(MAKE) -C platform/macos

else ifeq ($(TARGET_OS), linux)

export CFLAGS += -target $(TARGET) $(shell need --cflags platform/musl)
export PLATFORM_LDFLAGS += -target $(TARGET) $(shell need --libs platform/musl)

platform:
	$(MAKE) -C platform/musl

else ifeq ($(TARGET_OS), windows)

export CFLAGS += -target $(TARGET) $(shell need --cflags platform/windows)
export PLATFORM_LDFLAGS += -target $(TARGET) $(shell need --libs platform/windows)

platform:
	$(MAKE) -C platform/windows

else ifeq ($(TARGET_OS), freebsd)

export CFLAGS += -target $(TARGET) $(shell need --cflags platform/freebsd)
export PLATFORM_LDFLAGS += -target $(TARGET) $(shell need --libs platform/freebsd)

platform:
	:

else
$(error Unsupported platform $(TARGET_OS))
endif
