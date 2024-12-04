include $(ROOTDIR)/scripts/bdir.mk

OVERRIDES := $(shell find overrides -type f)

$(BDIR)/peer2.qcow2.gz: $(BDIR)/peer2.qcow2
	gzip -ck -9 $< > $@

$(BDIR)/peer2.qcow2: $(BDIR)/.apply
	test -f $<
	cp $(BDIR)/work.qcow2 $(BDIR)/peer2.qcow2

$(BDIR)/.apply: $(BDIR)/fresh.qcow2 $(OVERRIDES) mk
	doas ./mk combined $(BDIR)

$(BDIR)/fresh.qcow2: $(BDIR)/empty.qcow2 answerfile mk
	echo "a64=\"$$(cat answerfile | base64)\""
	echo 'echo "$$a64" | base64 -d > answerfile; head -n1 answerfile | cut -c 3-'
	BDIR=$(BDIR) ./mk fresh

$(BDIR)/empty.qcow2:
	mkdir -p $(BDIR)
	qemu-img create -f qcow2 $@ 10G
