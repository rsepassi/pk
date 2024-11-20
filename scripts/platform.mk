# Cross-platform support

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

ifeq ($(TARGET), x86_64-windows-gnu)
export O := obj
export EXE := .exe
LDFLAGS += -lws2_32 -luserenv -lole32 -liphlpapi -ldbghelp -lbcrypt
else
export O := o
export EXE :=
endif

ifeq ($(TARGET), x86_64-macos)
export CFLAGS += -isystem $(CURDIR)/platform/macos/include
else ifeq ($(TARGET), aarch64-macos)
export CFLAGS += -isystem $(CURDIR)/platform/macos/include
endif
