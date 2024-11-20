LIBNAME ?= $(notdir $(CURDIR))
HDRS ?= $(wildcard include/*.h) $(wildcard src/*.h)
SRCS ?= $(wildcard src/*.c)
OBJS := $(SRCS:.c=.$(O))

ifdef DEPS
	DEPS_OK := .deps.ok
endif

lib$(LIBNAME).a: $(OBJS) $(SRCS) $(HDRS) $(DEPS_OK) Makefile
	$(AR) rcs $@ $(OBJS)
	touch .build

%.$(O): %.c $(HDRS) $(DEPS_OK) Makefile
	$(CC) -c -o $@ -Iinclude $(CFLAGS) $(DEPS_CFLAGS) $<
