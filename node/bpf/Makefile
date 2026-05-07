# XDrop BPF Makefile — Phase 8: dual-ELF architecture

CLANG ?= clang

# Compiler flags
CFLAGS := -O2 -g -Wall -target bpf -D__BPF__
CFLAGS += -I./headers

.PHONY: all clean

all: xdrop_main.elf xdrop_gate.elf

xdrop_main.elf: xdrop_main.c xdrop.h headers/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c xdrop_main.c -o xdrop_main.elf

xdrop_gate.elf: xdrop_gate.c xdrop.h headers/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c xdrop_gate.c -o xdrop_gate.elf

clean:
	rm -f xdrop_main.elf xdrop_gate.elf
