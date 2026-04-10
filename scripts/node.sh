#!/usr/bin/env bash
# XDrop Node Agent — Service Manager
# Usage: ./scripts/node.sh <start|stop|restart|status|logs>
#
# Expects node/config.yaml to exist. Copy node/config.example.yaml to get started.
# Must be run as root (XDP requires CAP_NET_ADMIN).

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[node]${NC} $*"; }
warn()  { echo -e "${YELLOW}[node]${NC} $*"; }
die()   { echo -e "${RED}[node] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$ROOT/node"
AGENT_BIN="$NODE_DIR/xdrop-agent"
CONFIG="$NODE_DIR/config.yaml"
LOG_FILE="/tmp/xdrop-agent.log"
PORT="${PORT:-8080}"

check_root() {
    [[ $EUID -eq 0 ]] || die "Must be run as root (XDP requires CAP_NET_ADMIN)"
}

is_running() {
    pgrep -f "xdrop-agent" &>/dev/null
}

do_start() {
    check_root
    [[ -f "$AGENT_BIN" ]] || die "Binary not found: $AGENT_BIN — run ./scripts/build-node.sh first"
    [[ -f "$CONFIG"    ]] || die "Config not found: $CONFIG — copy config.example.yaml and edit it"

    if is_running; then
        warn "Agent already running (PID $(pgrep -f xdrop-agent))"
        return 0
    fi

    info "Starting node agent..."
    # Start from NODE_DIR so relative paths (bpf/xdrop.elf) resolve correctly
    cd "$NODE_DIR"
    nohup "$AGENT_BIN" --config "$CONFIG" >"$LOG_FILE" 2>&1 &
    sleep 2

    if is_running; then
        info "Agent started (PID $(pgrep -f xdrop-agent))"
        info "Logs: $LOG_FILE"
    else
        die "Agent failed to start — check $LOG_FILE\n$(tail -20 "$LOG_FILE" 2>/dev/null)"
    fi
}

do_stop() {
    check_root
    if is_running; then
        info "Stopping agent (PID $(pgrep -f xdrop-agent))..."
        pkill -f "xdrop-agent" || true
        sleep 1
        is_running && pkill -9 -f "xdrop-agent" || true
        info "Stopped"
    else
        warn "Agent is not running"
    fi
}

do_status() {
    echo ""
    echo -e "${BOLD}=== XDrop Node Status ===${NC}"
    echo ""

    if is_running; then
        echo -e "  Process : ${GREEN}running${NC} (PID $(pgrep -f xdrop-agent))"
    else
        echo -e "  Process : ${RED}stopped${NC}"
        echo ""
        return 0
    fi

    # API health check (node API requires auth)
    NODE_KEY=$(grep 'node_api_key' "$CONFIG" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if curl -sf -H "X-API-Key: $NODE_KEY" "http://localhost:$PORT/api/v1/health" | grep -q "healthy" 2>/dev/null; then
        echo -e "  API     : ${GREEN}healthy${NC} → http://localhost:$PORT"
    else
        echo -e "  API     : ${YELLOW}not responding${NC}"
    fi

    # Stats
    STATS=$(curl -sf -H "X-API-Key: $NODE_KEY" \
        "http://localhost:$PORT/api/v1/stats" 2>/dev/null || true)
    if [[ -n "$STATS" ]]; then
        echo ""
        echo -e "  Rules   : $(echo "$STATS" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("rules_count","-"))' 2>/dev/null || echo '-')"
        echo -e "  Whitelist: $(echo "$STATS" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("whitelist_count","-"))' 2>/dev/null || echo '-')"
        XDP=$(echo "$STATS" | python3 -c 'import sys,json; x=json.load(sys.stdin).get("xdp_info",{}); print(x.get("mode","-"),"| ifaces:", ",".join(i["name"] for i in x.get("interfaces",[])))' 2>/dev/null || echo '-')
        echo -e "  XDP     : $XDP"
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
        echo "  start    Start node agent (requires root)"
        echo "  stop     Stop node agent"
        echo "  restart  Stop then start"
        echo "  status   Show process, API health and XDP state"
        echo "  logs     Tail live log output"
        echo ""
        echo "Environment:"
        echo "  PORT     Node API port (default: 8080)"
        exit 1
        ;;
esac
