# XDrop Node Makefile

.PHONY: all bpf agent clean install uninstall

all: bpf agent

# Build BPF program
bpf:
	$(MAKE) -C bpf

# Build Go agent
# Same order as scripts/build-node.sh: XDROP_VERSION, then git describe only when the repository root is the checkout.
ROOT := $(realpath $(CURDIR)/..)
VERSION := $(or $(XDROP_VERSION),$(shell [ "$$(git -C $(ROOT) rev-parse --show-toplevel 2>/dev/null)" = "$(ROOT)" ] && git -C $(ROOT) describe --tags --always --dirty),unknown)
agent:
	cd agent && go build -ldflags "-X github.com/littlewolf9527/xdrop/node/agent/api.Version=$(VERSION)" -o ../xdrop-agent .

# Clean all
clean:
	$(MAKE) -C bpf clean
	rm -f xdrop-agent

# Install (run as root)
install: all
	cp xdrop-agent /usr/local/bin/
	cp xdrop-agent.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Run: systemctl enable --now xdrop-agent"

# Uninstall
uninstall:
	systemctl stop xdrop-agent || true
	systemctl disable xdrop-agent || true
	rm -f /usr/local/bin/xdrop-agent
	rm -f /etc/systemd/system/xdrop-agent.service
	systemctl daemon-reload
