include $(ROOTDIR)/scripts/bdir.mk

DO_RESERVED_IP := 24.199.69.99
DO_SPACE := https://peer2.sfo3.digitaloceanspaces.com
DO_PEER2_IMG_ID := 172069981
DO_PEER2_VPC_ID := a69c789c-5bab-4057-a852-652a875e53fa
DO_PEER2_DID := 461475209
DO_PEER2_SSHQUIC_FIREWALL_ID := 5c2c4b60-305e-443d-98f4-05df10a62e03
ISTUDIOS_SSH_MD5 := ec:25:0d:e9:e2:85:95:0e:ed:4c:b8:39:2f:b4:03:91
DO_CURL := curl -s \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $(DO_TOKEN)"

TAG ?= make
DID ?= $(DO_PEER2_DID)

.PHONY: \
	default list tag mktag create delete assignip assignfirewall firewalls \
	rebuild ssh scp imgmnt imgumnt imginstall imgupload imgls imgget imgshow \
	imghide
default:
	echo "specify a command"

# ==============================================================================
# DIGITAL OCEAN
# ==============================================================================
#
# https://docs.digitalocean.com/reference/api/api-reference
#
# SSH key fingerprint
# ssh-keygen -l -E md5 -f ~/.ssh/istudios.pub
#
# make --silent service T=list | jq .droplets[0].id
#
# Firewall: ssh-quic
#   SSH: TCP 22
#   QUIC: UDP 443
#
# To make the root droplet:
#   create
#   assignfirewall
#   assignip

list:
	$(DO_CURL) -X GET \
		"https://api.digitalocean.com/v2/droplets?tag_name=$(TAG)"

tag:
	$(DO_CURL) -X POST \
		-d '{"resources":[{"resource_id":"$(DID)","resource_type":"droplet"}]}' \
		"https://api.digitalocean.com/v2/tags/$(TAG)/resources" 

mktag:
	$(DO_CURL) -X POST \
		-d '{"name":"$(TAG)"}' \
		"https://api.digitalocean.com/v2/tags"

create:
	$(DO_CURL) -X POST \
		-d '{"name":"$(NAME)", "size":"s-1vcpu-512mb-10gb", "region":"sfo3", "image":"$(DO_PEER2_IMG_ID)", "vpc_uuid":"$(DO_PEER2_VPC_ID)", "ssh_keys": ["$(ISTUDIOS_SSH_MD5)"], "with_droplet_agent":false, "tags": ["$(TAG)", "make"]}' \
		"https://api.digitalocean.com/v2/droplets"

delete:
	$(DO_CURL) -X DELETE \
		"https://api.digitalocean.com/v2/droplets?tag_name=$(TAG)"

assignip:
	$(DO_CURL) -X POST \
		-d '{"type":"assign","droplet_id":$(DID)}' \
		"https://api.digitalocean.com/v2/reserved_ips/$(DO_RESERVED_IP)/actions"

assignfirewall:
	$(DO_CURL) -X POST \
		-d '{"droplet_ids":["$(DID)"]}' \
		"https://api.digitalocean.com/v2/firewalls/$(DO_PEER2_SSHQUIC_FIREWALL_ID)/droplets"

firewalls:
	$(DO_CURL) -X GET "https://api.digitalocean.com/v2/firewalls"

rebuild:
	$(DO_CURL) -X POST \
		-d '{"type":"rebuild","image":"$(DO_PEER2_IMG_ID)"}' \
		"https://api.digitalocean.com/v2/droplets/$(DID)/actions"

# ==============================================================================
# ==============================================================================


# ==============================================================================
# SSH
# ==============================================================================
ssh:
	ssh -i ~/.ssh/istudios peer2@server.peer2.xyz

scp:
	scp -i ~/.ssh/istudios $(F) peer2@server.peer2.xyz:/root/$(notdir $(F))
# ==============================================================================
# ==============================================================================


# ==============================================================================
# QEMU qcow2 image
# ==============================================================================
imgmnt:
	modprobe nbd max_part=8
	qemu-nbd --connect=/dev/nbd0 $(IMG)
	mkdir -p $(BDIR)/peer2-mnt
	mount /dev/nbd0p3 $(BDIR)/peer2-mnt

imgumnt:
	umount $(BDIR)/peer2-mnt
	qemu-nbd --disconnect /dev/nbd0
	sleep 2
	rmmod nbd

imginstall:
	modprobe nbd max_part=8
	qemu-nbd --connect=/dev/nbd0 $(IMG)
	mkdir -p $(BDIR)/peer2-mnt
	mount /dev/nbd0p3 $(BDIR)/peer2-mnt
	rm -rf $(BDIR)/peer2-mnt/etc
	rm -rf $(BDIR)/peer2-mnt/home
	cp -rp rootfs/etc $(BDIR)/peer2-mnt/
	cp -rp rootfs/home $(BDIR)/peer2-mnt/
	umount $(BDIR)/peer2-mnt
	qemu-nbd --disconnect /dev/nbd0
	sleep 2
	rmmod nbd

# DigitalOcean Spaces
# https://docs.digitalocean.com/products/spaces/reference/s3cmd-usage/

imgupload:
	mkdir -p $(BDIR)/img
	gzip -ck -9 $(IMG) > $(BDIR)/img/$(notdir $(IMG)).gz
	s3cmd put file $(BDIR)/img/$(notdir $(IMG)).gz s3://peer2/$(notdir $(IMG)).gz
	$(MAKE) imgshow IMG=$(notdir $(IMG)).gz
	$(DO_CURL) -X POST \
		-d '{"name": "$(notdir $(IMG))", "url": "$(DO_SPACE)/$(notdir $(IMG)).gz", "distribution": "Unknown", "region": "sfo3", "description": "peer2 custom image", "tags":["$(TAG)", "make"]}' \
		"https://api.digitalocean.com/v2/images"
	$(MAKE) imghide IMG=$(notdir $(IMG)).gz

imgls:
	$(DO_CURL) -X GET \
		"https://api.digitalocean.com/v2/images?private=true"
	s3cmd ls s3://peer2

imgget:
	mkdir -p $(BDIR)/img
	s3cmd get s3://peer2/$(IMG) $(BDIR)/img/

imgshow:
	s3cmd setacl s3://peer2/$(IMG) --acl-public

imghide:
	s3cmd setacl s3://peer2/$(IMG) --acl-private



# ==============================================================================
# ==============================================================================
