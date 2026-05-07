#!/usr/bin/env bash
# T57: Dual-ELF presence check automation test.
#
# Verifies that the dual-ELF guard in build-node.sh correctly detects missing
# ELF artifacts and would cause a build failure.  The test does NOT run make
# (no BPF build environment required); it exercises the `[[ -f ... ]]` check
# logic extracted from build-node.sh using a controlled temporary directory.
#
# Usage:  bash scripts/test-dual-elf-check.sh
# Exit:   0 if all cases pass, 1 if any case fails.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0

TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

MAIN_ELF="$TMPDIR_WORK/xdrop_main.elf"
GATE_ELF="$TMPDIR_WORK/xdrop_gate.elf"

# Mirrors the dual-ELF presence guard from build-node.sh (lines 31-32).
dual_elf_check() {
    [[ -f "$MAIN_ELF" ]] || { echo "BPF compile failed — xdrop_main.elf not found" >&2; return 1; }
    [[ -f "$GATE_ELF" ]] || { echo "BPF compile failed — xdrop_gate.elf not found" >&2; return 1; }
    return 0
}

check() {
    local desc="$1" want_pass="$2"
    if dual_elf_check >/dev/null 2>&1; then
        actual_pass=true
    else
        actual_pass=false
    fi
    if [[ "$actual_pass" == "$want_pass" ]]; then
        echo -e "${GREEN}PASS${NC}: $desc"
        ((PASS++))
    else
        echo -e "${RED}FAIL${NC}: $desc (got pass=$actual_pass, want pass=$want_pass)"
        ((FAIL++))
    fi
}

# Ensure clean state.
rm -f "$MAIN_ELF" "$GATE_ELF"

# Case 1: both ELFs present → build check must pass.
touch "$MAIN_ELF" "$GATE_ELF"
check "both ELFs present → check passes" true

# Case 2: gate ELF missing → must detect and fail.
rm "$GATE_ELF"
check "gate ELF missing → check fails" false

# Case 3: both ELFs missing → must fail.
rm "$MAIN_ELF"
check "both ELFs missing → check fails" false

# Case 4: only gate ELF present (main missing) → must fail.
touch "$GATE_ELF"
check "only gate ELF present, main missing → check fails" false

# Case 5: only main ELF present (gate missing) → must fail.
rm "$GATE_ELF"
touch "$MAIN_ELF"
check "only main ELF present, gate missing → check fails" false

# Case 6: both present again (restore) → must pass.
touch "$GATE_ELF"
check "both ELFs restored → check passes" true

echo ""
echo -e "${BOLD}T57 Results: $PASS passed, $FAIL failed${NC}"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
