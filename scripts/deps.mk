DEPS_CFLAGS := `need-cflags $(DEPS)`
DEPS_LDFLAGS := `need-libs $(DEPS)`
DEPS_CLEAN := $(addsuffix -clean, $(DEPS))

.PHONY: deps $(DEPS)
deps: $(DEPS)
$(DEPS):
	$(MAKE) -C $(ROOTDIR)/$@

.PHONY: clean-deps $(DEPS_CLEAN)
clean-deps: $(DEPS_CLEAN) $(CLEAN_ALL_EXTRAS)
$(DEPS_CLEAN):
	$(MAKE) -C $(@:-clean=) clean
