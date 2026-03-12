#!/usr/bin/env bash
# XDrop Controller — Service Manager
# Usage: ./scripts/controller.sh <start|stop|restart|status|logs>
#
# Expects controller/config.yaml to exist. Copy controller/config.example.yaml to get started.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[controller]${NC} $*"; }
warn()  { echo -e "${YELLOW}[controller]${NC} $*"; }
die()   { echo -e "${RED}[controller] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_DIR="$ROOT/controller"
CTRL_BIN="$CTRL_DIR/xdrop-controller"
CONFIG="$CTRL_DIR/config.yaml"
LOG_FILE="/tmp/xdrop-controller.log"
PORT="${PORT:-8000}"

is_running() {
    pgrep -f "xdrop-controller" &>/dev/null
}

do_start() {
    [[ -f "$CTRL_BIN" ]] || die "Binary not found: $CTRL_BIN — run ./scripts/build-controller.sh first"
    [[ -f "$CONFIG"   ]] || die "Config not found: $CONFIG — copy config.example.yaml and edit it"

    if is_running; then
        warn "Controller already running (PID $(pgrep -f xdrop-controller))"
        return 0
    fi

    info "Starting controller..."
    nohup "$CTRL_BIN" --config "$CONFIG" >"$LOG_FILE" 2>&1 &
    sleep 2

    if is_running; then
        info "Controller started (PID $(pgrep -f xdrop-controller))"
        info "Web UI: http://localhost:$PORT"
        info "Logs : $LOG_FILE"
    else
        die "Controller failed to start — check $LOG_FILE\n$(tail -20 "$LOG_FILE" 2>/dev/null)"
    fi
}

do_stop() {
    if is_running; then
        info "Stopping controller (PID $(pgrep -f xdrop-controller))..."
        pkill -f "xdrop-controller" || true
        sleep 1
        is_running && pkill -9 -f "xdrop-controller" || true
        info "Stopped"
    else
        warn "Controller is not running"
    fi
}

do_status() {
    echo ""
    echo -e "${BOLD}=== XDrop Controller Status ===${NC}"
    echo ""

    if is_running; then
        echo -e "  Process : ${GREEN}running${NC} (PID $(pgrep -f xdrop-controller))"
    else
        echo -e "  Process : ${RED}stopped${NC}"
        echo ""
        return 0
    fi

    # API health
    if curl -sf "http://localhost:$PORT/health" | grep -q "healthy" 2>/dev/null; then
        echo -e "  API     : ${GREEN}healthy${NC} → http://localhost:$PORT"
    else
        echo -e "  API     : ${YELLOW}not responding${NC}"
    fi

    # Nodes
    NODES=$(curl -sf "http://localhost:$PORT/api/v1/nodes" 2>/dev/null || true)
    if [[ -n "$NODES" ]]; then
        TOTAL=$(echo "$NODES"  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("count",0))' 2>/dev/null || echo 0)
        ONLINE=$(echo "$NODES" | python3 -c 'import sys,json; ns=json.load(sys.stdin).get("nodes",[]); print(sum(1 for n in ns if n.get("status")=="online"))' 2>/dev/null || echo 0)
        echo -e "  Nodes   : ${GREEN}${ONLINE}${NC}/${TOTAL} online"

        echo "$NODES" | python3 -c '
import sys, json
nodes = json.load(sys.stdin).get("nodes", [])
for n in nodes:
    status = n.get("status","?")
    mark = "\033[32m✓\033[0m" if status == "online" else "\033[31m✗\033[0m"
    print(f"    {mark}  {n[\"name\"]:20s}  {n[\"endpoint\"]:30s}  {status}")
' 2>/dev/null || true
    fi
    echo ""
}

do_logs() {
    [[ -f "$LOG_FILE" ]] || die "Log file not found: $LOG_FILE"
    tail -f "$LOG_FILE"
}

CMD="${1:-}"
case "$CMD" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; sleep 1; do_start ;;
    status)  do_status ;;
    logs)    do_logs ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "  start    Start controller"
        echo "  stop     Stop controller"
        echo "  restart  Stop then start"
        echo "  status   Show process, API health and node states"
        echo "  logs     Tail live log output"
        echo ""
        echo "Environment:"
        echo "  PORT     Controller API port (default: 8000)"
        exit 1
        ;;
esac
