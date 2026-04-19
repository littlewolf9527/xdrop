#!/usr/bin/env bash
# Phase 0 baseline E2E test for the goebpf → cilium/ebpf migration.
#
# Exercises a full CRUD lifecycle against a running Controller + Node:
#   1. Push 50 mixed rules (exact 5-tuple + CIDR + rate_limit) via batch API.
#   2. Push 10 whitelist entries via batch API.
#   3. Verify every rule/entry landed on the Node (Node API /api/v1/rules,
#      /api/v1/whitelist).
#   4. Delete half (25 rules + 5 whitelist entries) via batch API.
#   5. Verify counts decremented on the Node.
#   6. Delete the remainder and verify clean state.
#
# Usage (run on the lab gateway):
#   ./scripts/phase0-e2e.sh [--keep] [--wipe] [--out <dir>]
#
# Flags:
#   --keep         Do not delete rules on exit (for post-test inspection).
#   --wipe         DESTRUCTIVE: delete ALL controller rules + whitelist entries
#                  before running. Requires extra guards (see below).
#   --out <dir>    Write JSON snapshots + log to <dir>. Default: /tmp/xdrop-phase0-<ts>.
#
# Env overrides:
#   CTRL_URL       Controller base URL (default http://localhost:8000)
#   NODE_URL       Node base URL       (default http://localhost:8080)
#   CTRL_KEY       Controller external API key (auto-read from controller/config.yaml)
#   NODE_KEY       Node API key                (auto-read from node/config.yaml)
#
# DESTRUCTIVE-WIPE GUARDS (--wipe only, all three must hold):
#   1. `PHASE0_WIPE_I_UNDERSTAND=1` must be set in the environment — explicit ack.
#   2. `CTRL_URL` host must be in the allow-list: localhost / 127.0.0.1 / ::1.
#      Override with `PHASE0_WIPE_ALLOW_REMOTE=1` (NOT recommended).
#   3. Pre-wipe rule count must be <= `PHASE0_WIPE_MAX_RULES` (default 200).
#      Override with a larger value if the lab genuinely holds more.
#
# CLEANUP BEHAVIOR:
#   The script tracks every rule/whitelist ID it creates and registers an EXIT
#   trap. On any failure (or normal completion when --keep is not set), it
#   best-effort deletes the IDs it created during this run. --keep skips the
#   trap-based cleanup.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[phase0]${NC} $*"; }
warn() { echo -e "${YELLOW}[phase0]${NC} $*"; }
die()  { echo -e "${RED}[phase0] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP=0
WIPE=0
OUT_DIR="/tmp/xdrop-phase0-$(date +%Y%m%d-%H%M%S)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep) KEEP=1; shift ;;
        --wipe) WIPE=1; shift ;;
        --out)  OUT_DIR="$2"; shift 2 ;;
        *) die "Unknown arg: $1" ;;
    esac
done

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/phase0-e2e.log"
exec > >(tee -a "$LOG") 2>&1

CTRL_URL="${CTRL_URL:-http://localhost:8000}"
NODE_URL="${NODE_URL:-http://localhost:8080}"

# Auto-load keys from config.yaml if not provided.
if [[ -z "${CTRL_KEY:-}" ]]; then
    CTRL_KEY=$(awk '!/^[[:space:]]*#/ && /external_api_key:/{print $2; exit}' "$ROOT/controller/config.yaml" 2>/dev/null | tr -d '"' || true)
fi
if [[ -z "${NODE_KEY:-}" ]]; then
    NODE_KEY=$(awk '!/^[[:space:]]*#/ && /node_api_key:/{print $2; exit}' "$ROOT/node/config.yaml" 2>/dev/null | tr -d '"' || true)
fi
[[ -n "$CTRL_KEY" ]] || die "CTRL_KEY not set and not found in controller/config.yaml"
[[ -n "$NODE_KEY" ]] || die "NODE_KEY not set and not found in node/config.yaml"

CH=(-H "X-API-Key: $CTRL_KEY" -H 'Content-Type: application/json')
NH=(-H "X-API-Key: $NODE_KEY")

info "Output dir: $OUT_DIR"
info "Controller: $CTRL_URL"
info "Node:       $NODE_URL"

# ---- cleanup trap (AUD-PHASE0-002) ------------------------------------------
# Track everything we create during this run so a partial-failure exit can
# best-effort roll back. IDs are appended on every successful create.
CREATED_RULE_IDS=()
CREATED_WL_IDS=()

cleanup_on_exit() {
    local rc=$?
    if (( KEEP == 1 )); then
        warn "cleanup trap: --keep set, leaving ${#CREATED_RULE_IDS[@]} rules + ${#CREATED_WL_IDS[@]} whitelist entries on controller"
        exit $rc
    fi
    if (( ${#CREATED_RULE_IDS[@]} == 0 && ${#CREATED_WL_IDS[@]} == 0 )); then
        exit $rc
    fi
    warn "cleanup trap (exit=$rc): rolling back ${#CREATED_RULE_IDS[@]} rules + ${#CREATED_WL_IDS[@]} whitelist entries"
    if (( ${#CREATED_RULE_IDS[@]} > 0 )); then
        local payload
        payload=$(printf '%s\n' "${CREATED_RULE_IDS[@]}" | jq -R . | jq -sc '{ids: .}')
        curl -sf -X DELETE "${CH[@]}" -d "$payload" "$CTRL_URL/api/v1/rules/batch" \
            > "$OUT_DIR/99-trap-delete-rules.json" 2>/dev/null || \
            warn "trap: failed to batch-delete created rules (manual cleanup needed)"
    fi
    for id in "${CREATED_WL_IDS[@]}"; do
        curl -sf -X DELETE "${CH[@]}" "$CTRL_URL/api/v1/whitelist/$id" >/dev/null 2>&1 || true
    done
    exit $rc
}
trap cleanup_on_exit EXIT

# ---- preflight ---------------------------------------------------------------
info "preflight: checking services"
curl -sf "$CTRL_URL/health" >/dev/null || die "Controller unreachable"
curl -sf "${NH[@]}" "$NODE_URL/api/v1/health" | grep -q healthy || die "Node unreachable"

# Initial state snapshot (rules + whitelist from both sides).
curl -sf "${CH[@]}" "$CTRL_URL/api/v1/rules"     > "$OUT_DIR/00-ctrl-rules-before.json" || true
curl -sf "${CH[@]}" "$CTRL_URL/api/v1/whitelist" > "$OUT_DIR/00-ctrl-whitelist-before.json" || true
curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules"     > "$OUT_DIR/00-node-rules-before.json" || true
curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" > "$OUT_DIR/00-node-whitelist-before.json" || true

# ---- destructive-wipe guards (AUD-PHASE0-001) + optional wipe ----------------
if (( WIPE == 1 )); then
    # Guard 1: explicit env ack.
    [[ "${PHASE0_WIPE_I_UNDERSTAND:-0}" == "1" ]] || die \
        "--wipe refused: set PHASE0_WIPE_I_UNDERSTAND=1 to confirm you understand this deletes ALL rules on $CTRL_URL"

    # Guard 2: hostname allow-list (localhost / 127.0.0.1 / ::1), unless overridden.
    WIPE_HOST=$(printf '%s' "$CTRL_URL" | sed -E 's|^https?://([^/:]+).*|\1|')
    case "$WIPE_HOST" in
        localhost|127.0.0.1|::1|'[::1]')
            : ;; # allowed
        *)
            [[ "${PHASE0_WIPE_ALLOW_REMOTE:-0}" == "1" ]] || die \
                "--wipe refused: CTRL_URL host '$WIPE_HOST' is not in the allow-list. Set PHASE0_WIPE_ALLOW_REMOTE=1 to override (DANGEROUS)."
            warn "PHASE0_WIPE_ALLOW_REMOTE=1 — wiping a REMOTE controller at $WIPE_HOST"
            ;;
    esac

    # Guard 3: rule-count sanity. Default cap = 200, tunable via env.
    WIPE_MAX_RULES="${PHASE0_WIPE_MAX_RULES:-200}"
    PRE_WIPE_COUNT=$(jq '.rules // [] | length' "$OUT_DIR/00-ctrl-rules-before.json")
    PRE_WIPE_WL=$(jq '.entries // [] | length' "$OUT_DIR/00-ctrl-whitelist-before.json")
    (( PRE_WIPE_COUNT <= WIPE_MAX_RULES )) || die \
        "--wipe refused: controller holds $PRE_WIPE_COUNT rules, exceeds PHASE0_WIPE_MAX_RULES=$WIPE_MAX_RULES. Raise the env var if this is really a lab."

    info "WIPE guards cleared: host=$WIPE_HOST rules=$PRE_WIPE_COUNT whitelist=$PRE_WIPE_WL cap=$WIPE_MAX_RULES"
    info "WIPE mode — deleting ALL controller rules + whitelist entries"
    RULE_IDS=$(jq -r '.rules // [] | .[] | .id' "$OUT_DIR/00-ctrl-rules-before.json")
    if [[ -n "$RULE_IDS" ]]; then
        PAYLOAD=$(printf '%s\n' $RULE_IDS | jq -R . | jq -sc '{ids: .}')
        curl -sf -X DELETE "${CH[@]}" -d "$PAYLOAD" "$CTRL_URL/api/v1/rules/batch" \
            > "$OUT_DIR/00-wipe-rules.json" || warn "wipe rules batch delete failed (continuing)"
    fi
    WL_IDS=$(jq -r '.entries // [] | .[] | .id' "$OUT_DIR/00-ctrl-whitelist-before.json")
    if [[ -n "$WL_IDS" ]]; then
        for id in $WL_IDS; do
            curl -sf -X DELETE "${CH[@]}" "$CTRL_URL/api/v1/whitelist/$id" >/dev/null || true
        done
    fi
    sleep 1
    curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules"     > "$OUT_DIR/00-node-rules-after-wipe.json"
    curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" > "$OUT_DIR/00-node-whitelist-after-wipe.json"
    NODE_RULES_BEFORE=0
    NODE_WL_BEFORE=0
    RULES_AFTER_WIPE=$(jq '.rules | length // 0'   "$OUT_DIR/00-node-rules-after-wipe.json")
    WL_AFTER_WIPE=$(jq '.entries | length // 0' "$OUT_DIR/00-node-whitelist-after-wipe.json")
    info "after wipe: node rules=$RULES_AFTER_WIPE whitelist=$WL_AFTER_WIPE"
    [[ "$RULES_AFTER_WIPE" == "0" ]] || die "wipe left $RULES_AFTER_WIPE rules on node"
    [[ "$WL_AFTER_WIPE"    == "0" ]] || die "wipe left $WL_AFTER_WIPE whitelist entries on node"
fi

if (( WIPE == 0 )); then
    NODE_RULES_BEFORE=$(jq '.rules | length // 0' "$OUT_DIR/00-node-rules-before.json")
    NODE_WL_BEFORE=$(jq '.entries | length // 0' "$OUT_DIR/00-node-whitelist-before.json")
fi
info "baseline (post-wipe if WIPE=1): node rules=$NODE_RULES_BEFORE whitelist=$NODE_WL_BEFORE"

# ---- build payloads ----------------------------------------------------------
# 50 rules: 20 exact 5-tuple + 15 CIDR + 10 rate_limit + 5 mixed-filter.
# All IPs in RFC 5737 / RFC 3849 test ranges. Ports 30000-30999.
build_payload() {
    python3 - <<'PY'
import json, random
random.seed(0xdead_beef)
rules = []

# 20 exact 5-tuple drops, random combos
for i in range(20):
    r = {"action": "drop", "name": f"e2e-exact-{i:02d}"}
    if i % 5 != 0: r["src_ip"]    = f"192.0.2.{10+i}"
    if i % 4 != 0: r["dst_ip"]    = f"198.51.100.{20+i}"
    if i % 3 != 0: r["src_port"]  = 30100 + i
    if i % 2 != 0: r["dst_port"]  = 30200 + i
    if i % 6 == 0: r["protocol"]  = "tcp"
    elif i % 6 == 3: r["protocol"] = "udp"
    rules.append(r)

# 15 CIDR drops, varying prefix length. Non-overlapping ranges.
cidrs = [
    "203.0.113.0/25", "203.0.113.128/26", "203.0.113.192/27",
    "203.0.113.224/28", "203.0.113.240/29", "203.0.113.248/30",
    "2001:db8::/33", "2001:db8:8000::/33",
    "203.0.114.0/24", "203.0.115.0/24", "203.0.116.0/24",
    "203.0.117.0/24", "203.0.118.0/24", "203.0.119.0/24",
    "203.0.120.0/24",
]
for i, c in enumerate(cidrs):
    r = {"action": "drop", "name": f"e2e-cidr-{i:02d}"}
    if i % 2 == 0: r["src_cidr"] = c
    else:          r["dst_cidr"] = c
    if i % 3 == 0: r["dst_port"] = 30300 + i
    rules.append(r)

# 10 rate_limit rules
for i in range(10):
    rules.append({
        "action": "rate_limit",
        "rate_limit": 100 + i * 10,
        "dst_port": 30400 + i,
        "protocol": "tcp",
        "name": f"e2e-rl-{i:02d}",
    })

# 5 mixed-filter rules (pkt_len + tcp_flags)
for i in range(5):
    r = {
        "action": "drop",
        "dst_port": 30500 + i,
        "protocol": "tcp",
        "tcp_flags": "SYN,!ACK",
        "name": f"e2e-filter-{i:02d}",
    }
    if i % 2 == 0:
        r["pkt_len_min"] = 60
        r["pkt_len_max"] = 1500
    rules.append(r)

whitelist = []
for i in range(10):
    w = {"name": f"e2e-wl-{i:02d}"}
    # Alternate src-only / dst-only / full 5-tuple
    if i % 3 == 0:
        w["src_ip"] = f"192.0.2.{100+i}"
    elif i % 3 == 1:
        w["dst_ip"] = f"198.51.100.{100+i}"
    else:
        w["src_ip"] = f"192.0.2.{150+i}"
        w["dst_ip"] = f"198.51.100.{150+i}"
        w["src_port"] = 30600 + i
        w["dst_port"] = 30700 + i
        w["protocol"] = "tcp"
    whitelist.append(w)

print(json.dumps({"rules": rules, "whitelist": whitelist}))
PY
}

PAYLOAD=$(build_payload)
RULE_COUNT=$(jq '.rules | length' <<<"$PAYLOAD")
WL_COUNT=$(jq '.whitelist | length' <<<"$PAYLOAD")
[[ "$RULE_COUNT" == "50" ]] || die "built payload has $RULE_COUNT rules, expected 50"
[[ "$WL_COUNT"   == "10" ]] || die "built payload has $WL_COUNT whitelist, expected 10"
info "payload: 50 rules + 10 whitelist prepared"
echo "$PAYLOAD" | jq '.' > "$OUT_DIR/01-payload.json"

# ---- push rules --------------------------------------------------------------
info "pushing 50 rules via batch API"
RULES_BODY=$(jq '{rules: .rules}' <<<"$PAYLOAD")
RESP=$(curl -sf -X POST "${CH[@]}" -d "$RULES_BODY" "$CTRL_URL/api/v1/rules/batch")
echo "$RESP" > "$OUT_DIR/02-rules-batch-resp.json"

# Track any created IDs FIRST, before any validation `die`, so the trap can
# roll back even a partial-success batch.
jq -r '.rules[].id' <<<"$RESP" > "$OUT_DIR/02-rule-ids.txt"
while IFS= read -r rid; do
    [[ -n "$rid" ]] && CREATED_RULE_IDS+=("$rid")
done < "$OUT_DIR/02-rule-ids.txt"

ADDED=$(jq '.added // 0' <<<"$RESP")
FAILED=$(jq '.failed // 0' <<<"$RESP")
info "  added=$ADDED failed=$FAILED (tracked ${#CREATED_RULE_IDS[@]} ids for cleanup)"
[[ "$FAILED" == "0" ]] || die "rules batch had $FAILED failures"
[[ "$ADDED"  == "50" ]] || die "rules batch added $ADDED, expected 50"

info "pushing 10 whitelist entries (one-by-one; no batch endpoint)"
WL_ADDED=0
: > "$OUT_DIR/03-whitelist-responses.jsonl"
for i in $(seq 0 9); do
    ENTRY=$(jq -c ".whitelist[$i]" <<<"$PAYLOAD")
    RESP=$(curl -sf -X POST "${CH[@]}" -d "$ENTRY" "$CTRL_URL/api/v1/whitelist")
    echo "$RESP" >> "$OUT_DIR/03-whitelist-responses.jsonl"
    WL_ID=$(jq -r '.entry.id // empty' <<<"$RESP")
    [[ -n "$WL_ID" ]] && CREATED_WL_IDS+=("$WL_ID")
    WL_ADDED=$((WL_ADDED + 1))
done
info "  added=$WL_ADDED (one-by-one)"
[[ "$WL_ADDED" == "10" ]] || die "whitelist push added $WL_ADDED, expected 10"

# Also persist the ID list to a file (used by the half-delete section below).
printf '%s\n' "${CREATED_WL_IDS[@]}" > "$OUT_DIR/03-whitelist-ids.txt"

# ---- wait for sync + verify --------------------------------------------------
info "waiting for sync (polling node for 50 new rules)"
for attempt in $(seq 1 20); do
    NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
    NEW=$((NODE_RULES - NODE_RULES_BEFORE))
    if (( NEW >= 50 )); then
        break
    fi
    sleep 0.5
done
NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
NODE_WL=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" | jq '.entries | length // 0')
info "after push: node rules=$NODE_RULES (+$((NODE_RULES-NODE_RULES_BEFORE))) whitelist=$NODE_WL (+$((NODE_WL-NODE_WL_BEFORE)))"

curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules"     > "$OUT_DIR/04-node-rules-after-push.json"
curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" > "$OUT_DIR/04-node-whitelist-after-push.json"

(( NODE_RULES - NODE_RULES_BEFORE == 50 )) || die "Node rule count did not match (expected +50)"
(( NODE_WL    - NODE_WL_BEFORE    == 10 )) || die "Node whitelist count did not match (expected +10)"

# ---- delete half -------------------------------------------------------------
info "deleting first 25 rules + 5 whitelist entries"
HALF_RULES=$(head -25 "$OUT_DIR/02-rule-ids.txt" | jq -R . | jq -sc '{ids: .}')
RESP=$(curl -sf -X DELETE "${CH[@]}" -d "$HALF_RULES" "$CTRL_URL/api/v1/rules/batch")
echo "$RESP" > "$OUT_DIR/05-rules-batch-delete-half-resp.json"
DELETED=$(jq '.deleted // 0' <<<"$RESP")
[[ "$DELETED" == "25" ]] || die "rule half-delete reported $DELETED deleted, expected 25"

WL_DEL=0
: > "$OUT_DIR/05-whitelist-delete-half-responses.jsonl"
for id in $(head -5 "$OUT_DIR/03-whitelist-ids.txt"); do
    curl -sf -X DELETE "${CH[@]}" "$CTRL_URL/api/v1/whitelist/$id" \
        >> "$OUT_DIR/05-whitelist-delete-half-responses.jsonl" \
        && WL_DEL=$((WL_DEL + 1))
done
[[ "$WL_DEL" == "5" ]] || die "whitelist half-delete reported $WL_DEL deleted, expected 5"

info "waiting for sync (polling node for 25-rule decrement)"
for attempt in $(seq 1 20); do
    NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
    NEW=$((NODE_RULES - NODE_RULES_BEFORE))
    if (( NEW <= 25 )); then
        break
    fi
    sleep 0.5
done
NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
NODE_WL=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" | jq '.entries | length // 0')
info "after half-delete: node rules=$NODE_RULES (+$((NODE_RULES-NODE_RULES_BEFORE))) whitelist=$NODE_WL (+$((NODE_WL-NODE_WL_BEFORE)))"
(( NODE_RULES - NODE_RULES_BEFORE == 25 )) || die "Node rule count mismatch after half-delete (expected +25)"
(( NODE_WL    - NODE_WL_BEFORE    == 5 ))  || die "Node whitelist count mismatch after half-delete (expected +5)"

curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules"     > "$OUT_DIR/06-node-rules-after-half.json"
curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" > "$OUT_DIR/06-node-whitelist-after-half.json"

# Normal path: the half-delete already removed 25 rules + 5 whitelist from the
# tracking arrays, but the trap still holds references to them. Rebuild the
# arrays from the remaining half so a mid-remainder failure rolls back correctly.
CREATED_RULE_IDS=()
while IFS= read -r rid; do
    [[ -n "$rid" ]] && CREATED_RULE_IDS+=("$rid")
done < <(tail -n +26 "$OUT_DIR/02-rule-ids.txt")
CREATED_WL_IDS=()
while IFS= read -r wid; do
    [[ -n "$wid" ]] && CREATED_WL_IDS+=("$wid")
done < <(tail -n +6 "$OUT_DIR/03-whitelist-ids.txt")

# ---- clean up remainder ------------------------------------------------------
if (( KEEP == 1 )); then
    warn "--keep set; leaving remaining 25 rules + 5 whitelist on node"
    info "PASS (partial: kept half)"
    exit 0
fi

info "deleting remaining 25 rules + 5 whitelist entries"
REST_RULES=$(tail -n +26 "$OUT_DIR/02-rule-ids.txt" | jq -R . | jq -sc '{ids: .}')
curl -sf -X DELETE "${CH[@]}" -d "$REST_RULES" "$CTRL_URL/api/v1/rules/batch" \
    > "$OUT_DIR/07-rules-batch-delete-rest-resp.json"
: > "$OUT_DIR/07-whitelist-delete-rest-responses.jsonl"
for id in $(tail -n +6 "$OUT_DIR/03-whitelist-ids.txt"); do
    curl -sf -X DELETE "${CH[@]}" "$CTRL_URL/api/v1/whitelist/$id" \
        >> "$OUT_DIR/07-whitelist-delete-rest-responses.jsonl"
done

# Normal path: everything is deleted. Clear the trap-cleanup tracking so the
# EXIT handler doesn't try to re-delete already-gone IDs (harmless but noisy).
CREATED_RULE_IDS=()
CREATED_WL_IDS=()

info "waiting for sync (clean state)"
for attempt in $(seq 1 20); do
    NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
    NEW=$((NODE_RULES - NODE_RULES_BEFORE))
    if (( NEW == 0 )); then
        break
    fi
    sleep 0.5
done
NODE_RULES=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules" | jq '.rules | length // 0')
NODE_WL=$(curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" | jq '.entries | length // 0')
info "final: node rules=$NODE_RULES whitelist=$NODE_WL"
(( NODE_RULES == NODE_RULES_BEFORE )) || die "Node did not return to pre-test rule count"
(( NODE_WL    == NODE_WL_BEFORE ))    || die "Node did not return to pre-test whitelist count"

curl -sf "${NH[@]}" "$NODE_URL/api/v1/rules"     > "$OUT_DIR/08-node-rules-final.json"
curl -sf "${NH[@]}" "$NODE_URL/api/v1/whitelist" > "$OUT_DIR/08-node-whitelist-final.json"

info "PASS — Phase 0 E2E lifecycle completed cleanly"
info "Artifacts: $OUT_DIR"
