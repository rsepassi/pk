include $(ROOTDIR)/scripts/bdir.mk

DEPS_TARGET ?= deps

DEPS_CFLAGS := `need --cflags $(DEPS)`
DEPS_LDFLAGS := `need --libs $(DEPS)`

DEPS_CLEAN := $(addsuffix -clean, $(DEPS))
DEPS_BUILDS := $(addprefix $(ROOTDIR)/build/, $(addsuffix /.build, $(DEPS)))
DEPS_OK := $(BDIR)/.$(DEPS_TARGET).ok

$(DEPS_OK): $(DEPS_BUILDS)
	mkdir -p $(dir $(DEPS_OK))
	touch $(DEPS_OK)

.PHONY: $(DEPS_TARGET) $(DEPS)
$(DEPS_TARGET): $(DEPS)
$(DEPS):
	$(MAKE) -C $(ROOTDIR)/$@ deps
	mkdir -p $(ROOTDIR)/build/$@
	touch $(ROOTDIR)/build/$@/.lock
	flock $(ROOTDIR)/build/$@/.lock -c "$(MAKE) -C $(ROOTDIR)/$@"

.PHONY: clean-$(DEPS_TARGET) $(DEPS_CLEAN)
clean-$(DEPS_TARGET): $(DEPS_CLEAN) $(CLEAN_ALL_EXTRAS)
$(DEPS_CLEAN):
	$(MAKE) -C $(@:-clean=) clean
