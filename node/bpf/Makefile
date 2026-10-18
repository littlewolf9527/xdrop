# XDrop BPF Makefile — Phase 8: dual-ELF architecture

CLANG ?= clang
PYTHON ?= python3

COMBO_MASK_GEN := tools/extract_combo_masks.py
COMBO_MASK_HEADER := combo_masks.h

# Compiler flags
CFLAGS := -O2 -g -Wall -target bpf -D__BPF__
CFLAGS += -I./headers

# EXTRA_CFLAGS —— 给 Phase 1 里程碑 M0 用：
#   make EXTRA_CFLAGS=-DXDROP_CAND_N=4
# 直接 `make CFLAGS=...` 会把上面两行整个覆盖掉（:= 是立即赋值），所以留这个钩子。
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: all clean test abi-test verify-combo-masks

all: xdrop_main.elf xdrop_gate.elf

xdrop_main.elf: xdrop_main.c xdrop.h $(COMBO_MASK_HEADER) headers/bpf_helpers.h | verify-combo-masks
	$(CLANG) $(CFLAGS) -c xdrop_main.c -o xdrop_main.elf

# The checked-in table is generated evidence, not a hand-maintained second
# source of truth.  Regenerate to a temporary file on every main build and
# expose any ordered/content drift as a failing unified diff.
verify-combo-masks:
	@set -eu; tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' 0 1 2 3 15; \
	$(PYTHON) $(COMBO_MASK_GEN) --emit-c > "$$tmp"; \
	diff -u $(COMBO_MASK_HEADER) "$$tmp"

xdrop_gate.elf: xdrop_gate.c xdrop.h headers/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c xdrop_gate.c -o xdrop_gate.elf

clean:
	rm -f xdrop_main.elf xdrop_gate.elf

# Phase 0 · 跨语言 ABI 契约
#
# abi-test 先编 ELF 再跑 Go 测试——把「编译产物是测试的输入」这件事写进构建，
# 而不是靠人记得先 make。忘了先编，那个测试会红并告诉你跑什么命令。
#
# 该测试比对 ELF 里 map 的 key_size/value_size 与 Go 侧 unsafe.Sizeof，
# 是「改了 C 侧没改 Go 侧」唯一会变红的地方（internal_docs/tech-debt.md TD-010）。
abi-test: all
	cd ../agent && go test ./abi/ -v

# test 是 abi-test 的别名，供 CI 直接调用
test: abi-test
