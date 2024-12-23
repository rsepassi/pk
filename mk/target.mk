ifndef HOST
	OS := $(shell uname)
	ARCH := $(shell uname -m)
	ifeq ($(OS), Darwin)
		ifeq ($(ARCH), arm64)
			HOST := aarch64-macos
		else
			HOST := x86_64-macos
		endif
	else
		ifeq ($(ARCH), arm64)
			HOST := aarch64-linux-musl
		else
			HOST := x86_64-linux-musl
		endif
	endif
endif

ifndef TARGET
TARGET := $(HOST)
endif

ifneq ($(TARGET), $(HOST))
XCOMP := 1
endif

TARGET_ARCH := $(word 1, $(subst -, ,$(TARGET)))
TARGET_OS   := $(word 2, $(subst -, ,$(TARGET)))
HOST_ARCH := $(word 1, $(subst -, ,$(HOST)))
HOST_OS   := $(word 2, $(subst -, ,$(HOST)))
