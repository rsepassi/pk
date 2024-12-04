# Cross-platform support

# uname target detection
ifndef HOST
	OS := $(shell uname)
	ARCH := $(shell uname -m)
	ifeq ($(OS), Darwin)
		ifeq ($(ARCH), arm64)
			export HOST := aarch64-macos
		else
			export HOST := x86_64-macos
		endif
	else
		ifeq ($(ARCH), arm64)
			export HOST := aarch64-linux-musl
		else
			export HOST := x86_64-linux-musl
		endif
	endif
else
export HOST
endif

ifndef TARGET
export TARGET := $(HOST)
else
export TARGET
endif

export TARGET_ARCH := $(word 1, $(subst -, ,$(TARGET)))
export TARGET_OS   := $(word 2, $(subst -, ,$(TARGET)))
export HOST_ARCH := $(word 1, $(subst -, ,$(HOST)))
export HOST_OS   := $(word 2, $(subst -, ,$(HOST)))

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
export CFLAGS += `need --cflags platform/valgrind`
endif

# coverage
ifdef COVERAGE
export CFLAGS += -fprofile-instr-generate -fcoverage-mapping
export LDFLAGS += -fprofile-instr-generate -fcoverage-mapping
export EXEC_PREFIX := LLVM_PROFILE_FILE=$(BROOT)/coverage/default.profraw
endif

# clang
ifeq ($(USE_CLANG), 1)
export CFLAGS += --rtlib=compiler-rt
endif

.PHONY: platform

ifeq ($(TARGET_OS), macos)

export CFLAGS += -target $(TARGET) `need --cflags platform/macos`
export PLATFORM_LDFLAGS += -target $(TARGET)

platform:
	:

else ifeq ($(TARGET_OS), linux)

export CFLAGS += -target $(TARGET)
export PLATFORM_LDFLAGS += -target $(TARGET)

platform:
	:

else
$(error Unsupported platform $(TARGET_OS))
endif
