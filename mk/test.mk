.PHONY: test
test: deps test-deps
	$(MAKE) -f $(ROOTDIR)/mk/test2.mk test TEST_DEPS="$(TEST_DEPS) vendor/unity"
