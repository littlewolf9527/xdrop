# Makefile for XDP drop program

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Kernel headers path (adjust if needed)
KERNEL_HEADERS ?= /usr/include

# Compiler flags
CFLAGS := -O2 -g -Wall -target bpf
CFLAGS += -I$(KERNEL_HEADERS)
CFLAGS += -D__TARGET_ARCH_x86

# Source and target
SRC = xdp_drop.c
OBJ = xdp_drop.o

.PHONY: all clean load unload

all: $(OBJ)

$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

# Load XDP program to interface (usage: make load IFACE=eth0)
load: $(OBJ)
	@if [ -z "$(IFACE)" ]; then \
		echo "Usage: make load IFACE=<interface>"; \
		exit 1; \
	fi
	sudo ip link set dev $(IFACE) xdp obj $(OBJ) sec xdp

# Unload XDP program from interface (usage: make unload IFACE=eth0)
unload:
	@if [ -z "$(IFACE)" ]; then \
		echo "Usage: make unload IFACE=<interface>"; \
		exit 1; \
	fi
	sudo ip link set dev $(IFACE) xdp off

# Show XDP program status
status:
	@if [ -z "$(IFACE)" ]; then \
		echo "Usage: make status IFACE=<interface>"; \
		exit 1; \
	fi
	ip link show dev $(IFACE)

# View kernel trace log (for bpf_printk output)
trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
