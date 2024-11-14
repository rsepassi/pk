# Cross-platform support

ifndef OPT
export OPT := -O2
export ZIG_OPT := ReleaseFast
else
export OPT
export ZIG_OPT
endif

ifndef TARGET
export TARGET := x86_64-linux-musl
else
export TARGET
endif

ifeq ($(TARGET), x86_64-windows-gnu)
export O := obj
export EXE := .exe
LDFLAGS += -lws2_32 -luserenv -lole32 -liphlpapi -ldbghelp -lbcrypt
else
export O := o
export EXE :=
endif

ifeq ($(TARGET), x86_64-macos)
export CFLAGS += -isystem $(ROOTDIR)/vendor/platform/macos/include
else ifeq ($(TARGET), aarch64-macos)
export CFLAGS += -isystem $(ROOTDIR)/vendor/platform/macos/include
endif
