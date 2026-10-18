# Frozen pre-S2a source identity

These four original files were copied from HEAD `126b4cbbf7cdc1e73b0b345d1f6830a8e461eb3f`
before implementation. `manifest.json` records their original SHA-256 values.
They describe the historical table, including the two unreachable Go branches
and the C alias slots. They are test evidence, not active production headers.

The classifier test compiles the hash-certified original Go functions and
compares every Boolean input with the current functions. The evaluator loads
this explicit root with `pre-s2a`; the current source root uses `s2a`. Both
contracts enforce the fixed roster, masks, bitmap, order and source identities.
Never regenerate this directory from the current tree or swap contract labels.

Run from the repository root:

```sh
python3 node/agent/tools/check_s2a.py --root "$(pwd -P)"
bash node/agent/tools/mutation_check_combo.sh
python3 node/bpf/tools/test_extract_combo_masks.py
python3 internal_docs/plans/phase1/test_gate_mask_parity.py
make -C node/bpf verify-combo-masks
bash internal_docs/_verify_facts.sh
```

The local evaluator proves rule selection and action configuration only for
consistent snapshots with retired bits clear. Synthetic dirty-pin probes are
counterexamples outside that domain. No local result certifies BPF verifier
cost, kernel behavior, deployment safety, or token-bucket timing.
