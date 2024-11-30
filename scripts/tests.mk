ALL_TESTS := $(addprefix test/, $(TEST_DIRS))

.PHONY: test $(ALL_TESTS)
test: $(ALL_TESTS)
	echo TESTS OK

test-clean:
	find build -type d -name 'test' | xargs rm -rf

$(ALL_TESTS): platform scripts/test.mk scripts/tests.mk
	$(MAKE) -C vendor/unity
	$(MAKE) -C $(@:test/%=%) deps
	$(MAKE) -C $(@:test/%=%) test-deps 2>/dev/null || :
	$(MAKE) -C $(@:test/%=%)
	$(MAKE) -C $(@:test/%=%) test
