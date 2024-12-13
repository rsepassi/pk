include $(ROOTDIR)/scripts/bdir.mk

DO_RESERVED_IP := 24.199.69.99
DO_PEER2_IMG_ID := 172089670
DO_PEER2_VPC_ID := a69c789c-5bab-4057-a852-652a875e53fa
DO_PEER2_DID := 461475209
DO_PEER2_SSHQUIC_FIREWALL_ID := 5c2c4b60-305e-443d-98f4-05df10a62e03
ISTUDIOS_SSH_MD5 := ec:25:0d:e9:e2:85:95:0e:ed:4c:b8:39:2f:b4:03:91
DO_CURL := curl -s \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $(DO_TOKEN)"

TAG ?= make
DID ?= $(DO_PEER2_DID)
IMG ?= $(BDIR)/vmimage/peer2.qcow2
SRC ?= $(BROOT_ALL)/x86_64-linux-musl/cli/bin/cli
DST ?= /home/peer2/

.PHONY: \
	default list tag mktag create delete assignip assignfirewall firewalls \
	rebuild ssh scpto scpfrom imgmk

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

scpto:
	scp -i ~/.ssh/istudios $(SRC) peer2@server.peer2.xyz:$(DST)
scpfrom:
	scp -i ~/.ssh/istudios peer2@server.peer2.xyz:$(SRC) $(DST)
# ==============================================================================
# ==============================================================================


# ==============================================================================
# QEMU qcow2 image
# ==============================================================================
imgmk:
	$(MAKE) -C vmimage

# ==============================================================================
# ==============================================================================
