ALL_LIBS := $(addprefix lib/, $(LIB_DIRS))

.PHONY: $(ALL_LIBS)

$(ALL_LIBS): platform
	$(MAKE) -C $(@:lib/%=%) deps
	$(MAKE) -C $(@:lib/%=%)
