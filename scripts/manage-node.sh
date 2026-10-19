#!/usr/bin/env bash
# Usage: ./scripts/manage-node.sh {start|stop|restart|status|logs}
# PID file plus exact binary/config command verification; no process-name kill.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMP_DIR="$ROOT/node"
BIN="$COMP_DIR/xdrop-agent"
CONFIG="${XDROP_CONFIG:-$COMP_DIR/config.yaml}"
RUN_DIR="${XDROP_RUN_DIR:-$COMP_DIR/run}"
PID_FILE="$RUN_DIR/service.pid"
EXIT_FILE="$RUN_DIR/service.exit"
LOG_FILE="$RUN_DIR/service.log"
die() { printf '[node] ERROR: %s\n' "$*" >&2; exit 1; }
[[ $CONFIG == /* && $RUN_DIR == /* ]] || die 'XDROP_CONFIG and XDROP_RUN_DIR must be absolute paths'
[[ $# == 1 ]] || die "Usage: $0 {start|stop|restart|status|logs}"
case "$1" in start|stop|restart|status|logs) ;; *) die 'unknown command' ;; esac
pid=''
running() {
    [[ -f "$PID_FILE" ]] || return 1
    read -r pid < "$PID_FILE" || die 'unreadable PID file'
    case "$pid" in ''|*[!0-9]*) die 'invalid PID file' ;; esac
    [[ $pid -gt 1 ]] || die 'invalid PID'
    kill -0 "$pid" 2>/dev/null || return 1
    local actual
    actual=$(ps -p "$pid" -o args=) || die 'cannot verify PID identity'
    # A stale PID must never signal another executable or configuration.
    [[ $actual == "$BIN -config $CONFIG" ]] || die 'PID identity differs; inspect the PID file manually'
}
exit_result() {
    local code=unknown
    [[ ! -f "$EXIT_FILE" ]] || read -r code < "$EXIT_FILE"
    printf 'exit_code=%s\n' "$code"
}
start_service() {
    [[ $EUID == 0 ]] || die "node management requires root"
    [[ -x "$BIN" ]] || die 'binary missing; run scripts/build-node.sh first'
    [[ -f "$CONFIG" ]] || die 'configuration missing; initialize it before start'
    if running; then printf 'running pid=%s\n' "$pid"; return; fi
    rm -f "$PID_FILE" "$EXIT_FILE"
    # The supervisor reaps the child and records its actual wait status.
    nohup bash -c '
        cd "$5" || exit 1
        "$1" -config "$2" &
        child=$!
        printf "%s\n" "$child" > "$3"
        wait "$child"
        code=$?
        printf "%s\n" "$code" > "$4"
    ' xdrop-supervisor "$BIN" "$CONFIG" "$PID_FILE" "$EXIT_FILE" "$COMP_DIR" \
        >> "$LOG_FILE" 2>&1 < /dev/null &
    local i
    for ((i=0; i<50; i++)); do
        [[ -f "$PID_FILE" || -f "$EXIT_FILE" ]] && break
        sleep 0.1
    done
    sleep 1
    if ! running; then exit_result; die "startup failed; see $LOG_FILE"; fi
    printf 'running pid=%s log=%s\n' "$pid" "$LOG_FILE"
}
stop_service() {
    [[ $EUID == 0 ]] || die "node management requires root"
    if ! running; then printf 'stopped '; exit_result; return; fi
    kill -TERM "$pid" || die 'SIGTERM failed'
    local i
    for ((i=0; i<300; i++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            # wait status can be written just after the PID is reaped.
            for ((i=0; i<50; i++)); do
                [[ -f "$EXIT_FILE" ]] && break
                sleep 0.1
            done
            rm -f "$PID_FILE"
            printf 'stopped '; exit_result
            return
        fi
        sleep 0.1
    done
    die 'still running after 30 seconds; no SIGKILL sent'
}
sweep_link_pins() {
    # This agent owns the shared /sys/fs/bpf/xdrop namespace.
    # Only stop removes link pins; restart retains attachment, not policy.
    local pin
    for pin in /sys/fs/bpf/xdrop/link_*; do
        [[ -e "$pin" ]] || continue
        rm -f "$pin"
        printf 'removed link pin=%s\n' "$pin"
    done
    printf 'FF interface settings may remain; inspect interfaces before restoring them\n'
}
case "$1" in
    status)
        if running; then printf 'running pid=%s\n' "$pid"; else printf 'stopped '; exit_result; exit 3; fi
        ;;
    logs) [[ -f "$LOG_FILE" ]] || die 'log file missing'; exec tail -f "$LOG_FILE" ;;
    *)
        mkdir -p "$RUN_DIR"
        if ! mkdir "$RUN_DIR/manager.lock" 2>/dev/null; then
            [[ -d "$RUN_DIR/manager.lock" ]] || die "cannot create lock $RUN_DIR/manager.lock"
            die "lock $RUN_DIR/manager.lock exists: another management operation is running, or one was killed before releasing it; if none is running, remove it with: rmdir -- $(printf '%q' "$RUN_DIR/manager.lock")"
        fi
        trap 'rmdir "$RUN_DIR/manager.lock"' EXIT
        case "$1" in
            start) start_service ;;
            stop) if running; then stop_service; sweep_link_pins; else stop_service; fi ;;
            restart) stop_service; start_service ;;
        esac
        ;;
esac
