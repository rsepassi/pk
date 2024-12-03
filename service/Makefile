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

RESERVED_IP := 24.199.69.99
DO_CURL := curl -s \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $(DO_TOKEN)"
TAG ?= make

ifndef DO_TOKEN
	$(error Must specify DO_TOKEN)
endif

.PHONY: default list tag mktag create delete assignip assignfirewall firewalls
default:
	echo "specify a command"

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
		-d '{"name":"$(NAME)", "size":"s-1vcpu-512mb-10gb", "region":"sfo3", "image":"debian-12-x64", "ipv6":true, "vpc_uuid":"a69c789c-5bab-4057-a852-652a875e53fa", "ssh_keys": ["ec:25:0d:e9:e2:85:95:0e:ed:4c:b8:39:2f:b4:03:91"], "with_droplet_agent":false, "tags": ["$(TAG)", "make"]}' \
		"https://api.digitalocean.com/v2/droplets"

delete:
	$(DO_CURL) -X DELETE \
		"https://api.digitalocean.com/v2/droplets?tag_name=$(TAG)"

assignip:
	$(DO_CURL) -X POST \
		-d '{"type":"assign","droplet_id":$(DID)}' \
		"https://api.digitalocean.com/v2/reserved_ips/$(RESERVED_IP)/actions"

assignfirewall:
	$(DO_CURL) -X POST \
		-d '{"droplet_ids":[$(DID)]}' \
		"https://api.digitalocean.com/v2/firewalls/$(FIREWALL)/droplets"

firewalls:
	$(DO_CURL) -X GET "https://api.digitalocean.com/v2/firewalls"

ssh:
	ssh -i ~/.ssh/istudios root@server.peer2.xyz
