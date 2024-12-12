# Cross-platform support

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

# asan
ifdef ASAN
export CFLAGS += -fsanitize=address -fno-common
export LDFLAGS += -fsanitize=address

ifeq ($(TARGET_OS), linux)
	export LDFLAGS += -lunwind
endif
endif

# msan
ifdef MSAN
ifeq ($(TARGET_OS), linux)
export CFLAGS += -fsanitize=memory -fsanitize-memory-track-origins
export LDFLAGS += -fsanitize=memory -fsanitize-memory-track-origins -lunwind
endif
endif

# coverage
ifdef COVERAGE
export CFLAGS += -fprofile-instr-generate -fcoverage-mapping
export LDFLAGS += -fprofile-instr-generate -fcoverage-mapping
export EXEC_PREFIX := LLVM_PROFILE_FILE=$(BROOT)/coverage/default.profraw
endif

.PHONY: platform

ifeq ($(TARGET_OS), macos)

MACTARGET := $(TARGET)
ifeq ($(USE_CLANG), 1)
	MACTARGET := $(TARGET_ARCH)-apple-macosx13
endif

export CFLAGS += -target $(MACTARGET) `need --cflags platform/macos`
export PLATFORM_LDFLAGS += -target $(MACTARGET)

platform:
	@:

else ifeq ($(TARGET_OS), linux)

export CFLAGS += -target $(TARGET) `need --cflags platform/linux`
export PLATFORM_LDFLAGS += -target $(TARGET) `need --libs platform/linux`

platform:
	$(MAKE) -C platform/linux $(T)

else ifeq ($(TARGET_OS), freebsd)

BSDTARGET := $(TARGET)
ifeq ($(USE_CLANG), 1)
	BSDTARGET := $(TARGET_ARCH)-unknown-freebsd
endif

export CFLAGS += -target $(BSDTARGET) `need --cflags platform/freebsd`
export PLATFORM_LDFLAGS += -target $(BSDTARGET) `need --libs platform/freebsd`

platform:
	$(MAKE) -C platform/freebsd $(T)

else ifeq ($(TARGET_OS), windows)

WINTARGET := $(TARGET)
ifeq ($(USE_CLANG), 1)
	WINTARGET := $(TARGET_ARCH)-w64-mingw32
endif

export CFLAGS += -target $(WINTARGET) `need --cflags platform/windows`
export PLATFORM_LDFLAGS += -target $(WINTARGET) `need --libs platform/windows`

platform:
	$(MAKE) -C platform/windows $(T)

else

$(error Unsupported platform $(TARGET_OS))

endif
