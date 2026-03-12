# XDrop Node Makefile

.PHONY: all bpf agent clean install uninstall

all: bpf agent

# Build BPF program
bpf:
	$(MAKE) -C bpf

# Build Go agent
agent:
	cd agent && go build -o ../xdrop-agent .

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
