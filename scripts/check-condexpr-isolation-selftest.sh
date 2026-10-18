#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temp_base="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
case "$temp_base/" in
  "$root/"*) echo 'SELFTEST_FAIL TMPDIR must be outside the repository' >&2; exit 1 ;;
esac
scratch="$(mktemp -d "$temp_base/xdrop-condexpr-isolation.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
cd "$root"

# Only temporary copies are changed. The retained node cases each replace one file.
python3 - "$root" "$scratch" <<'PY'
import json
import pathlib
import sys

root, scratch = map(pathlib.Path, sys.argv[1:])
post_cut = root / "node/agent/bpf/xdp_mode.go"
post_cut_source = post_cut.read_text()
if post_cut_source.count("import (") != 1:
    raise SystemExit("SELFTEST_FAIL expected exactly one post-cut import block")
post_cut_source = post_cut_source.replace("import (", 'import (\n\t"github.com/littlewolf9527/xdrop/node/agent/condexpr"', 1)
post_cut_source += "\nfunc td073IsolationNegativeControl() { _ = condexpr.Compile }\n"
case_dir = scratch / "post_cut_file_imports_condexpr"
case_dir.mkdir()
post_cut_copy = case_dir / "xdp_mode.go"
post_cut_copy.write_text(post_cut_source)
(case_dir / "overlay.json").write_text(json.dumps({"Replace": {str(post_cut): str(post_cut_copy)}}) + "\n")

planned = root / "node/agent/api/condition_groups.go"
planned_source = planned.read_text()
for name, text in {
    "planned_file_extra_edge": planned_source + "\nfunc cut53UnplannedEdge() { _ = condexpr.Compile }\n",
    "planned_edge_missing": planned_source.replace("return ValidateCanonicalConditionRule(*r)", "return nil", 1),
}.items():
    case_dir = scratch / name
    case_dir.mkdir()
    copy = case_dir / "condition_groups.go"
    copy.write_text(text)
    (case_dir / "overlay.json").write_text(json.dumps({"Replace": {str(planned): str(copy)}}) + "\n")

commit = root / "node/agent/api/commit_preflight.go"
commit_source = commit.read_text()
for name, text in {
    "commit_unplanned_edge": commit_source + "\nfunc cut55UnplannedEdge() { _ = condexpr.Compile }\n",
    "commit_planned_edge_missing": commit_source.replace("row, err := EncodeConditionValue(rules)", "row, err := ConditionValue{}, error(nil)", 1),
}.items():
    case_dir = scratch / name
    case_dir.mkdir()
    copy = case_dir / "commit_preflight.go"
    copy.write_text(text)
    (case_dir / "overlay.json").write_text(json.dumps({"Replace": {str(commit): str(copy)}}) + "\n")
PY

expect_red() {
  local name="$1" reason="$2" rc=0
  go run scripts/check-condexpr-isolation.go -overlay "$scratch/$name/overlay.json" >"$scratch/$name/output.txt" 2>&1 || rc=$?
  printf 'SELFTEST_CASE %s\n' "$name"
  cat "$scratch/$name/output.txt"
  printf 'SELFTEST_GATE_EXIT case=%s exit=%d\n' "$name" "$rc"
  if [[ "$rc" -eq 0 ]] || ! grep -Fq -- "$reason" "$scratch/$name/output.txt"; then
    printf 'SELFTEST_FAIL case=%s expected nonzero exit and reason: %s\n' "$name" "$reason" >&2
    exit 1
  fi
}

expect_red post_cut_file_imports_condexpr 'node/agent/bpf/xdp_mode.go: imports new package github.com/littlewolf9527/xdrop/node/agent/condexpr'
expect_red planned_file_extra_edge 'node/agent/api/condition_groups.go: references condexpr.Compile'
expect_red planned_edge_missing 'planned edge count node/agent/api/condition_groups.go#normalizeConditionRule: references ValidateCanonicalConditionRule got=0 want=1'

expect_green() {
  local name="$1" rc=0
  shift
  go run scripts/check-condexpr-isolation.go "$@" >"$scratch/$name.txt" 2>&1 || rc=$?
  printf 'SELFTEST_CASE %s\n' "$name"
  cat "$scratch/$name.txt"
  printf 'SELFTEST_GATE_EXIT case=%s exit=%d\n' "$name" "$rc"
  if [[ "$rc" -ne 0 ]] || ! grep -Eq '^B1_PRODUCTION_ISOLATION existing_files=[0-9]+ protected_files=5 incoming_references=0 new_init_entries=0$' "$scratch/$name.txt"; then
    printf 'SELFTEST_FAIL case=%s must exit zero with incoming_references=0\n' "$name" >&2
    exit 1
  fi
}

expect_red commit_unplanned_edge 'node/agent/api/commit_preflight.go: references condexpr.Compile'
expect_red commit_planned_edge_missing 'planned edge count node/agent/api/commit_preflight.go#encodeCommitGroup: references EncodeConditionValue got=0 want=1'

expect_green original
echo 'SELFTEST_PASS negative_cases=5 positive_cases=1 original_incoming_references=0'
