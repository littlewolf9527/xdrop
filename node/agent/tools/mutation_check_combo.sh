#!/usr/bin/env bash
# The Python harness preserves the five M1 mutations and adds both S2a
# classifiers' condition, reachability, mapping and dependency mutations.
set -eu
exec python3 "$(dirname "$0")/mutation_check_combo.py"
