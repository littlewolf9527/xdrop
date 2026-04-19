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
    # -x matches the process name exactly (against /proc/<pid>/comm).
    # The earlier -f form matched any command line containing
    # "xdrop-agent" — including the very bash invoking this script —
    # which caused false "already running" positives during `restart`
    # and `start` races. Stick with -x.
    pgrep -x xdrop-agent &>/dev/null
}

# agent_pid prints the single running agent PID, or empty if none.
# Uses the same exact-match rule as is_running.
agent_pid() {
    pgrep -x xdrop-agent 2>/dev/null | head -1
}

# sweep_link_pins removes any /sys/fs/bpf/xdrop/link_* files so the
# corresponding XDP attachments detach from their interfaces. Safe
# when no pins exist. Called only from `stop`, NOT from `restart` —
# keeping the pins alive across restart is what gives Phase 4 its
# zero-gap program-swap behaviour (LoadPinnedLink + Update on the
# next start).
sweep_link_pins() {
    shopt -s nullglob
    local pins=( /sys/fs/bpf/xdrop/link_* )
    shopt -u nullglob
    (( ${#pins[@]} )) || return 0
    for p in "${pins[@]}"; do
        info "Unlinking pinned XDP link: $p"
        rm -f "$p"
    done
}

# kill_agent_process kills the agent binary without touching pin files.
# Shared between `stop` (which then sweeps pins) and `restart` (which
# preserves pins for zero-gap reattach).
kill_agent_process() {
    if is_running; then
        info "Stopping agent (PID $(agent_pid))..."
        pkill -x xdrop-agent || true
        sleep 1
        is_running && pkill -9 -f "xdrop-agent" || true
    else
        warn "Agent is not running"
    fi
}

do_start() {
    check_root
    [[ -f "$AGENT_BIN" ]] || die "Binary not found: $AGENT_BIN — run ./scripts/build-node.sh first"
    [[ -f "$CONFIG"    ]] || die "Config not found: $CONFIG — copy config.example.yaml and edit it"

    if is_running; then
        warn "Agent already running (PID $(agent_pid))"
        return 0
    fi

    info "Starting node agent..."
    # Start from NODE_DIR so relative paths (bpf/xdrop.elf) resolve correctly
    cd "$NODE_DIR"
    nohup "$AGENT_BIN" --config "$CONFIG" >"$LOG_FILE" 2>&1 &
    sleep 2

    if is_running; then
        info "Agent started (PID $(agent_pid))"
        info "Logs: $LOG_FILE"
    else
        die "Agent failed to start — check $LOG_FILE\n$(tail -20 "$LOG_FILE" 2>/dev/null)"
    fi
}

do_stop() {
    check_root
    kill_agent_process
    # Since v2.5 (Phase 4 link pinning) the agent can leave a pinned
    # XDP link behind — `Link.Close()` during graceful shutdown only
    # drops the userspace fd, kernel XDP stays attached via the pin
    # file. That's the feature that makes restart zero-gap, but it
    # means `stop` alone would leave packet filtering active with no
    # process tracking it — a confusing semantic for operators. So
    # `stop` explicitly sweeps the pins too. Use `restart` if you
    # actually want the pin preserved across a process cycle.
    sweep_link_pins
    info "Stopped (agent killed, XDP link pins swept)"
}

# do_stop_keep_pins is the restart-time stop: kill the process but
# leave /sys/fs/bpf/xdrop/link_* in place so the next start takes the
# zero-gap LoadPinnedLink + Update path instead of a fresh attach.
do_stop_keep_pins() {
    check_root
    kill_agent_process
}

do_status() {
    echo ""
    echo -e "${BOLD}=== XDrop Node Status ===${NC}"
    echo ""

    if is_running; then
        echo -e "  Process : ${GREEN}running${NC} (PID $(agent_pid))"
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
    restart) do_stop_keep_pins; sleep 1; do_start ;;
    status)  do_status ;;
    logs)    do_logs ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "  start    Start node agent (requires root)"
        echo "  stop     Stop node agent AND detach XDP (sweeps link pins)"
        echo "  restart  Stop process only, then start — preserves link"
        echo "           pins for Phase 4 zero-gap attachment"
        echo "  status   Show process, API health and XDP state"
        echo "  logs     Tail live log output"
        echo ""
        echo "Environment:"
        echo "  PORT     Node API port (default: 8080)"
        exit 1
        ;;
esac
