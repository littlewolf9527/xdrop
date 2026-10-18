#!/usr/bin/env bash
# Build both BPF ELF objects and the Linux node agent.
# Usage: ./scripts/build-node.sh [bpf|agent|all]
set -euo pipefail
info() { printf '[build-node] %s\n' "$*"; }
die() { printf '[build-node] ERROR: %s\n' "$*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$ROOT/node"
[[ $(uname -s) == Linux ]] || die 'build the node on Linux'
build_bpf() {
    for tool in clang make python3; do command -v "$tool" >/dev/null || die "$tool not found"; done
    info 'make -C node/bpf clean; make -C node/bpf all'
    make -C "$NODE_DIR/bpf" clean
    make -C "$NODE_DIR/bpf" all
    for elf in xdrop_main.elf xdrop_gate.elf; do
        [[ -s "$NODE_DIR/bpf/$elf" ]] || die "$elf missing"
    done
}
build_agent() {
    command -v go >/dev/null || die 'go not found'
    # XDROP_VERSION wins; otherwise git describe, but only when ROOT is itself the checkout (a source archive has no .git).
    local version=${XDROP_VERSION:-}
    if [[ -z $version ]] && command -v git >/dev/null && [[ $(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null) == "$(cd "$ROOT" && pwd -P)" ]]; then
        version=$(git -C "$ROOT" describe --tags --always --dirty)
    fi
    if [[ -z $version ]]; then
        version=unknown
        info 'WARNING: not a git checkout and XDROP_VERSION is unset; the agent reports version "unknown"'
    fi
    info "go build -mod=readonly -buildvcs=false -trimpath (version $version)"
    (cd "$NODE_DIR/agent" && go build -mod=readonly -buildvcs=false -trimpath \
        -ldflags "-X github.com/littlewolf9527/xdrop/node/agent/api.Version=$version" \
        -o "$NODE_DIR/xdrop-agent" .)
    [[ -x "$NODE_DIR/xdrop-agent" ]] || die 'agent executable missing'
}
[[ $# -le 1 ]] || die "Usage: $0 [bpf|agent|all]"
case "${1:-all}" in
    bpf) build_bpf ;;
    agent) build_agent ;;
    all) build_bpf; build_agent ;;
    *) die "Usage: $0 [bpf|agent|all]" ;;
esac
