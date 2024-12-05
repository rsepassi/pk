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

