#!/usr/bin/env bash
# XDrop Node — Build Script
# Usage: ./scripts/build-node.sh [bpf|agent|all]
#
#   bpf    Build BPF/XDP kernel program (requires clang)
#   agent  Build Go agent binary
#   all    Build both (default)
#
# Must be run on a Linux host with clang and Go installed.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build-node]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build-node]${NC} $*"; }
die()   { echo -e "${RED}[build-node] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$ROOT/node"
BPF_DIR="$NODE_DIR/bpf"
AGENT_DIR="$NODE_DIR/agent"
AGENT_BIN="$NODE_DIR/xdrop-agent"
BPF_ELF="$BPF_DIR/xdrop.elf"

build_bpf() {
    info "Compiling BPF program..."
    command -v clang &>/dev/null || die "clang not found. Install with: apt install clang"
    make -C "$BPF_DIR" clean
    make -C "$BPF_DIR"
    [[ -f "$BPF_ELF" ]] || die "BPF compile failed — $BPF_ELF not found"
    info "BPF build OK → $BPF_ELF"
}

build_agent() {
    info "Compiling Go agent..."
    command -v go &>/dev/null || die "go not found. Install from https://go.dev/dl/"
    (cd "$AGENT_DIR" && go mod tidy && go build -buildvcs=false -trimpath -o "$AGENT_BIN" .)
    [[ -f "$AGENT_BIN" ]] || die "Agent compile failed"
    info "Agent build OK → $AGENT_BIN"
}

CMD="${1:-all}"
case "$CMD" in
    bpf)   build_bpf ;;
    agent) build_agent ;;
    all)   build_bpf; build_agent ;;
    *) die "Unknown command '$CMD'. Usage: $0 [bpf|agent|all]" ;;
esac

echo -e "\n${BOLD}${GREEN}✓ Node build complete${NC}"
