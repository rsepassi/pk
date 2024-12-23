# Cross-platform support

# object/executable suffixes
ifeq ($(TARGET_OS), windows)
O := obj
EXE := .exe
else
O := o
EXE :=
endif

# valgrind
ifdef VALGRIND
VALGRIND := 1
EXEC_PREFIX := valgrind -s --leak-check=full --show-leak-kinds=all \
	--track-origins=yes --num-callers=16
CFLAGS += `need --cflags platform/valgrind`
endif

# asan
ifdef ASAN
ASAN := 1
CFLAGS += -fsanitize=address -fno-common
LDFLAGS += -fsanitize=address

ifeq ($(TARGET_OS), linux)
	LDFLAGS += -lunwind
endif
endif

# msan
ifdef MSAN
MSAN := 1
ifeq ($(TARGET_OS), linux)
CFLAGS += -fsanitize=memory -fsanitize-memory-track-origins
LDFLAGS += -fsanitize=memory -fsanitize-memory-track-origins -lunwind
endif
endif

# coverage
ifdef COVERAGE
CFLAGS += -fprofile-instr-generate -fcoverage-mapping
LDFLAGS += -fprofile-instr-generate -fcoverage-mapping
EXEC_PREFIX := LLVM_PROFILE_FILE=$(BROOT)/coverage/default.profraw
endif

.PHONY: platform

ifeq ($(TARGET_OS), macos)

MACTARGET := $(TARGET)
ifeq ($(CC), clang-19)
	MACTARGET := $(TARGET_ARCH)-apple-macosx13
endif

CFLAGS += -target $(MACTARGET) `need --cflags platform/macos`
PLATFORM_LDFLAGS += -target $(MACTARGET) `need --libs platform/macos`

platform:
	@:

else ifeq ($(TARGET_OS), linux)

CFLAGS += `need --cflags platform/linux`
PLATFORM_LDFLAGS += `need --libs platform/linux`

ifeq ($(XCOMP), 1)
CFLAGS += -target $(TARGET) 
PLATFORM_LDFLAGS += -target $(TARGET) 
endif

ifneq ($(CC), tcc)
CFLAGS += --sysroot=$(BROOT)/platform/linux/sysroot 
PLATFORM_LDFLAGS += --sysroot=$(BROOT)/platform/linux/sysroot \
  -resource-dir=$(BROOT)/platform/linux/linux_alpine/compiler-rt \
  -static-pie -z relro -z now -z noexecstack
endif

platform:
	$(MAKE) -C platform/linux $(PLATFORM_T)

else ifeq ($(TARGET_OS), freebsd)

BSDTARGET := $(TARGET)
ifeq ($(CC), clang-19)
	BSDTARGET := $(TARGET_ARCH)-unknown-freebsd
endif

CFLAGS += -target $(BSDTARGET) `need --cflags platform/freebsd`
PLATFORM_LDFLAGS += -target $(BSDTARGET) `need --libs platform/freebsd`

platform:
	$(MAKE) -C platform/freebsd $(PLATFORM_T)

else ifeq ($(TARGET_OS), windows)

WINTARGET := $(TARGET)
ifeq ($(CC), clang-19)
	WINTARGET := $(TARGET_ARCH)-w64-mingw32
endif

CFLAGS += -target $(WINTARGET) `need --cflags platform/windows`
PLATFORM_LDFLAGS += -target $(WINTARGET) `need --libs platform/windows`

platform:
	$(MAKE) -C platform/windows $(PLATFORM_T)

else

$(error Unsupported platform $(TARGET_OS))

endif
