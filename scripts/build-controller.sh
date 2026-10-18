#!/usr/bin/env bash
# Build the console and controller/core executable.
# Usage: ./scripts/build-controller.sh [web|go|all]
set -euo pipefail
info() { printf '[build-controller] %s\n' "$*"; }
die() { printf '[build-controller] ERROR: %s\n' "$*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_DIR="$ROOT/controller"
WEB_DIR="$ROOT/console"
CTRL_BIN="$CTRL_DIR/xdrop-controller"
build_web() {
    command -v node >/dev/null || die 'node not found'
    command -v npm >/dev/null || die 'npm not found'
    if [[ ${XDROP_SKIP_NPM_CI:-0} == 1 ]]; then
        [[ -d "$WEB_DIR/node_modules" ]] || die 'offline build needs existing console/node_modules'
        info 'XDROP_SKIP_NPM_CI=1: skipping npm ci; using existing dependencies'
    else
        info "cd $WEB_DIR && npm ci"
        (cd "$WEB_DIR" && npm ci)
    fi
    info "cd $WEB_DIR && npm run build"
    (cd "$WEB_DIR" && npm run build)
    [[ -s "$CTRL_DIR/core/webui/build/index.html" ]] || die 'console build/index.html missing'
    info "Frontend build OK -> $CTRL_DIR/core/webui/build"
}
build_go() {
    command -v go >/dev/null || die 'go not found'
    [[ -s "$CTRL_DIR/core/webui/build/index.html" ]] || die "frontend missing: run '$0 web' first"
    info "cd $CTRL_DIR && go build -tags webui -trimpath -o $CTRL_BIN ./cmd/xdrop-controller"
    (cd "$CTRL_DIR" && go build -tags webui -trimpath -o "$CTRL_BIN" ./cmd/xdrop-controller)
    [[ -x "$CTRL_BIN" ]] || die 'controller executable missing'
    info "Controller build OK -> $CTRL_BIN"
}
[[ $# -le 1 ]] || die "Usage: $0 [web|go|all]"
case "${1:-all}" in
    web) build_web ;;
    go) build_go ;;
    all) build_web; build_go ;;
    *) die "Usage: $0 [web|go|all]" ;;
esac
