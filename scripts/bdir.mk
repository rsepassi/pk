.PHONY: bdir
bdir: build/.keep
build/.keep:
	mkdir -p build
	touch build/.keep

