.PHONY: clean
clean:
	rm -rf *.a *.lib *.o *.obj src/*.a src/*.lib src/*.o src/*.obj .build .zig-cache zig-out $(CLEAN_EXTRAS)
