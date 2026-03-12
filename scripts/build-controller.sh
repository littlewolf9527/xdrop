#!/usr/bin/env bash
# XDrop Controller — Build Script
# Usage: ./scripts/build-controller.sh [web|go|all]
#
#   web  Build Vue 3 frontend (requires node + npm)
#   go   Build Go controller binary (embeds pre-built frontend)
#   all  Build frontend then Go (default)
#
# The Go binary embeds the frontend via go:embed, so 'web' must run before 'go'.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build-ctrl]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build-ctrl]${NC} $*"; }
die()   { echo -e "${RED}[build-ctrl] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_DIR="$ROOT/controller"
WEB_DIR="$CTRL_DIR/web"
CTRL_BIN="$CTRL_DIR/xdrop-controller"

build_web() {
    info "Building frontend (Vue 3)..."
    command -v node &>/dev/null || die "node not found. Install from https://nodejs.org"
    command -v npm  &>/dev/null || die "npm not found."
    (cd "$WEB_DIR" && npm install && npm run build)
    [[ -d "$WEB_DIR/dist" ]] || die "Frontend build failed — dist/ not found"
    info "Frontend build OK → $WEB_DIR/dist"
}

build_go() {
    info "Compiling Go controller..."
    command -v go &>/dev/null || die "go not found. Install from https://go.dev/dl/"
    [[ -d "$WEB_DIR/dist" ]] || die "dist/ not found — run 'web' step first (frontend is embedded)"
    (cd "$CTRL_DIR" && go mod tidy && go build -buildvcs=false -trimpath -o "$CTRL_BIN" ./cmd/controller)
    [[ -f "$CTRL_BIN" ]] || die "Controller compile failed"
    info "Controller build OK → $CTRL_BIN"
}

CMD="${1:-all}"
case "$CMD" in
    web) build_web ;;
    go)  build_go ;;
    all) build_web; build_go ;;
    *) die "Unknown command '$CMD'. Usage: $0 [web|go|all]" ;;
esac

echo -e "\n${BOLD}${GREEN}✓ Controller build complete${NC}"
