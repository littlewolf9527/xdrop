#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for target in "$root/node/agent/condexpr" "$root/controller/core/condexpr"; do
  mkdir -p "$target"
  # Remove only stale generated Go files, then copy without rewriting bytes.
  for file in "$target"/*.go; do
    [[ -e "$file" ]] || continue
    [[ -f "$root/shared/condexpr/${file##*/}" ]] || rm -- "$file"
  done
  cp "$root/shared/condexpr/"*.go "$target/"
done
