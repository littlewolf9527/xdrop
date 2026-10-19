# XDrop Node Makefile

.PHONY: all bpf agent clean

all: bpf agent

# Build BPF program
bpf:
	$(MAKE) -C bpf

# Build Go agent: delegates to scripts/build-node.sh so both entry points share flags, OS check and version rules.
agent:
	../scripts/build-node.sh agent

# Clean all
clean:
	$(MAKE) -C bpf clean
	rm -f xdrop-agent
