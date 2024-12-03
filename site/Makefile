include $(ROOTDIR)/scripts/bdir.mk

.PHONY: build upload
build:
	mkdir -p $(BDIR)/build
	cp src/index.html $(BDIR)/build

$(BDIR)/site.zip: build
	zip -r $@ $(BDIR)/build

upload: $(BDIR)/site.zip
	curl \
		-H "Content-Type: application/zip" \
		-H "Authorization: Bearer $(NETLIFY_TOKEN)" \
		--data-binary "@$<" \
		https://api.netlify.com/api/v1/sites/peer2.xyz/deploys
