include $(ROOTDIR)/mk/bdir.mk

LIBTCC_SRCS := \
	src/libtcc.c \
	src/tccasm.c \
	src/tccdbg.c \
	src/tccelf.c \
	src/tccgen.c \
	src/tccpp.c \
	src/tccrun.c \
	src/x86_64-gen.c \
	src/x86_64-link.c \
	src/i386-asm.c
LIBTCC_HDRS := \
	$(wildcard src/*.h) \
	$(BDIR)/gen/tccdefs_.h
LIBTCC_OBJS := $(LIBTCC_SRCS:.c=.$(O))
LIBTCC_OBJS := $(addprefix $(BDIR)/libtcc/, $(LIBTCC_OBJS))
LIBTCC := $(BDIR)/libtcc.a

LIBTCC1_SRCS := \
	src/lib/alloca-bt.S \
	src/lib/alloca.S \
	src/lib/atomic.S \
	src/lib/builtin.c \
	src/lib/dsohandle.c \
	src/lib/libtcc1.c \
	src/lib/stdatomic.c \
	src/lib/tcov.c \
	src/lib/va_list.c
LIBTCC1_OBJS := $(LIBTCC1_SRCS:.c=.$(O))
LIBTCC1_OBJS := $(LIBTCC1_OBJS:.S=.$(O))
LIBTCC1_OBJS := $(addprefix $(BDIR)/libtcc1/, $(LIBTCC1_OBJS))
LIBTCC1 := $(BDIR)/libtcc1.a

SUPPORT_SRCS := \
	src/lib/bt-exe.c \
	src/lib/bt-log.c \
	src/lib/runmain.c \
	src/lib/bcheck.c
SUPPORT_OBJS := $(SUPPORT_SRCS:.c=.$(O))
SUPPORT_OBJS := $(addprefix $(BDIR)/libtcc1/, $(SUPPORT_OBJS))

TCC := $(BDIR)/tcc
C2STR := $(BROOT_HOST)/vendor/tcc/gen/c2str

CONFIG_DIR := -DCONFIG_TCCDIR=\"$(BDIR)/lib/tcc\"

CFLAGS += \
	-DONE_SOURCE=0 \
	-DTCC_MUSL \
	-DTCC_TARGET_X86_64 \
	-Iinclude \
	-I$(BDIR)/gen \
	-Wdeclaration-after-statement \
	-Wno-format-truncation \
	-Wno-pointer-sign \
	-Wno-sign-compare \
	-Wno-string-plus-int \
	-Wno-unused-result \
	-Wno-implicit-int-conversion \
	-Wno-implicit-float-conversion \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-fno-strict-aliasing

.PHONY: default
default: $(BDIR)/.build

$(BDIR)/.build: $(TCC) $(LIBTCC1) $(SUPPORT_OBJS)
	mkdir -p $(BDIR)/bin $(BDIR)/include $(BDIR)/lib/tcc
	cp $(TCC) $(BDIR)/bin/
	cp src/libtcc.h $(BDIR)/include
	cp $(LIBTCC) $(BDIR)/lib
	cp $(LIBTCC1) $(BDIR)/lib/tcc/
	cp $(SUPPORT_OBJS) $(BDIR)/lib/tcc/
	touch $@

$(BDIR)/libtcc1/src/lib/bcheck.o: src/lib/bcheck.c $(TCC)
	$(TCC) -c $< -o $@ -Isrc -bt -DTCC_MUSL

$(LIBTCC1): $(LIBTCC1_OBJS)
	mkdir -p $(dir $@)
	$(AR) rcs $@ $(LIBTCC1_OBJS)

$(BDIR)/libtcc1/%.$(O): %.c $(TCC)
	mkdir -p $(dir $@)
	$(TCC) -c -o $@ -Isrc $<

$(BDIR)/libtcc1/%.$(O): %.S $(TCC)
	mkdir -p $(dir $@)
	$(TCC) -c -o $@ $<

$(TCC): $(BDIR)/libtcc/src/tcc.o $(LIBTCC)
	$(CCLD) -o $@ $(LDFLAGS) $^ $(PLATFORM_LDFLAGS) -lc

$(LIBTCC): $(LIBTCC_OBJS)
	mkdir -p $(dir $@)
	$(AR) rcs $@ $(LIBTCC_OBJS)

$(BDIR)/libtcc/%.$(O): %.c $(LIBTCC_HDRS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $(CFLAGS) $(CONFIG_DIR) $<

$(BDIR)/gen/tccdefs_.h: include/tccdefs.h $(C2STR)
	mkdir -p $(dir $@)
	$(C2STR) $< $@

$(C2STR): src/conftest.c
	mkdir -p $(dir $@)
	$(CC) -DC2STR -o $@ $<

include $(ROOTDIR)/mk/deps.mk
