# XDrop BPF Makefile

CLANG ?= clang
LLC ?= llc

# Compiler flags
CFLAGS := -O2 -g -Wall -target bpf -D__BPF__
CFLAGS += -I./headers

# Source and target
SRC = xdrop.c
OBJ = xdrop.elf

.PHONY: all clean

all: $(OBJ)

$(OBJ): $(SRC) xdrop.h headers/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)

# Verify that bpf program is valid (requires Linux with bpftool)
verify: $(OBJ)
	@echo "Verifying BPF program..."
	@bpftool prog load $(OBJ) /sys/fs/bpf/xdrop_test type xdp 2>&1 || true
	@bpftool prog show name xdrop_firewall 2>/dev/null || echo "Note: Run on Linux to verify"
	@rm -f /sys/fs/bpf/xdrop_test 2>/dev/null || true
