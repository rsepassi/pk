include $(ROOTDIR)/scripts/bdir.mk

DEPS_TARGET ?= deps

DEPS_OK := $(BDIR)/.$(DEPS_TARGET).ok
DEPS_BUILDS := $(addprefix $(BROOT)/, $(addsuffix /.build, $(DEPS)))
$(DEPS_OK): $(DEPS_BUILDS)
	mkdir -p $(dir $(DEPS_OK))
	touch $(DEPS_OK)

.PHONY: $(DEPS_TARGET) $(DEPS)
$(DEPS_TARGET): $(DEPS)
$(DEPS):
	$(MAKE) -C $(ROOTDIR)/$@ deps
	mkdir -p $(BROOT)/$@
	touch $(BROOT)/$@/.lock
	flock $(BROOT)/$@/.lock -c "$(MAKE) -C $(ROOTDIR)/$@"

DEPS_CLEAN := $(addsuffix -clean, $(DEPS))
.PHONY: clean-$(DEPS_TARGET) $(DEPS_CLEAN)
clean-$(DEPS_TARGET): $(DEPS_CLEAN) $(CLEAN_ALL_EXTRAS)
$(DEPS_CLEAN):
	$(MAKE) -C $(@:-clean=) clean
