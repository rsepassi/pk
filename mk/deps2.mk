# deps.mk defines a phony rule "deps" that will build all targets specified in
# $(DEPS_ARG). Each dependency is responsible for touching a .build file if it
# updated. If any of the dependencies rebuild, then deps will touch a .deps.ok
# file.
#
# By running the deps target up front unconditionally and then depending on
# the .deps.ok file, targets will be correctly rebuilt if a (transitive)
# dependency updates.
#
# Example:
#
# A depends on B and C
# C depends on D
# Edit something in D
# Make A
#
# make A deps
#   make B deps
#     up-to-date (empty set)
#   make B
#     up-to-date
#   make C deps
#     make D deps
#     	up-to-date (empty set)
#     make D
#     	modified, build
#     	touch .build
#     D/.build modified
#     touch .deps.ok
#   make C
#     C: .deps.ok ...
#       .deps.ok modified, rebuild
#       touch .build
#   C/.build modified
#   touch .deps.ok
# make A
# 	A: .deps.ok ...
# 	  .deps.ok modified, rebuild
# 	  touch .build
include $(ROOTDIR)/mk/bdir.mk

DEPS_OK := $(BDIR)/.deps.ok
DEPS_BUILDS := $(addprefix $(BROOT)/, $(addsuffix /.build, $(DEPS_ARG)))

.PHONY: deps deps-check $(DEPS_ARG)
deps: $(DEPS_ARG)
	$(MAKE) -f $(ROOTDIR)/mk/deps2.mk deps-check
deps-check: $(DEPS_OK)

$(DEPS_OK): $(DEPS_BUILDS)
	mkdir -p $(dir $@)
	touch $@

$(DEPS_ARG):
		@mkdir -p $(BROOT)/$@; \
		if [ ! -f $(BROOT)/$@/.lock ]; then touch $(BROOT)/$@/.lock; fi; \
		flock $(BROOT)/$@/.lock -c "build1.sh $@"

DEPS_CLEAN := $(addsuffix -clean, $(DEPS_ARG))
.PHONY: clean-deps $(DEPS_CLEAN)
clean-deps: $(DEPS_CLEAN) $(CLEAN_ALL_EXTRAS)
$(DEPS_CLEAN):
	$(MAKE) -C $(@:-clean=) clean DEPS_ARG=
