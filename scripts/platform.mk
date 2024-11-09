# Cross-platform support

export TARGET := x86_64-linux-musl

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
