#!/usr/bin/env python3
"""Compile and exercise each named combo guard, only in retained /tmp copies."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
MOD = ROOT / "node/agent"
WORK = Path(tempfile.mkdtemp(prefix="s2a-combo-", dir="/tmp"))
COPY = WORK / "node/agent"
shutil.copytree(MOD, COPY)
SOURCE = MOD / "api/combo.go"
PRISTINE = SOURCE.read_text()
WATCH = [p for p in (MOD / "api").glob("*.go")]
BEFORE = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in WATCH}
ENV = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", TMPDIR="/tmp")
MATRIX = []


def run(name, source, tests, expected=None):
    (COPY / "api/combo.go").write_text(source)
    cmd = ["go", "test", "-json", "-count=1", "./api/", "-run", tests]
    p = subprocess.run(cmd, cwd=COPY, env=ENV, capture_output=True, text=True)
    (WORK / (name + ".log")).write_text(p.stdout + p.stderr)
    events = [json.loads(line) for line in p.stdout.splitlines()]
    failed = {e.get("Test") for e in events if e["Action"] == "fail" and e.get("Test")}
    passed = {e.get("Test") for e in events if e["Action"] == "pass" and e.get("Test")}
    output = "".join(e.get("Output", "") for e in events)
    (COPY / "api/combo.go").write_text(PRISTINE)
    restored = hashlib.sha256((COPY / "api/combo.go").read_bytes()).hexdigest()
    assert restored == hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "restoration drift"
    if expected is not None:
        recovered = subprocess.run(cmd, cwd=COPY, env=ENV, capture_output=True, text=True)
        (WORK / (name + "-recovered.log")).write_text(recovered.stdout + recovered.stderr)
        recovery = [json.loads(line) for line in recovered.stdout.splitlines()]
        assert recovered.returncode == 0 and any(e["Action"] == "pass" and e.get("Test") for e in recovery)
        assert not any(e["Action"] in ("skip", "fail") for e in recovery)
    else:
        recovered = p
    row = {"test": expected[0] if expected else tests, "description": name,
           "expected_red": expected[1] if expected else None,
           "actual_red": next((line.strip() for line in output.splitlines() if expected and expected[1] in line), ""),
           "rc": p.returncode, "recovered_rc": recovered.returncode,
           "restored_sha256": {"api/combo.go": restored}, "failed_tests": sorted(failed),
           "passed_tests": sorted(passed), "log": str(WORK / (name + ".log"))}
    MATRIX.append(row)
    (WORK / "matrix.json").write_text(json.dumps(MATRIX, indent=2) + "\n")
    assert not any(e["Action"] == "skip" for e in events), (name, "SKIP")
    if expected is None:
        assert p.returncode == 0 and passed and not failed, (name, output, p.stderr)
        print(f"{name}: PASS tests={len(passed)} RC=0")
    else:
        test, red = expected
        assert source != PRISTINE, (name, "empty mutation")
        assert p.returncode != 0 and test in failed and red in output, (name, failed, output, p.stderr)
        assert "build failed" not in output and "[no test files]" not in output, (name, output)
        point = next(line.strip() for line in output.splitlines() if red in line)
        print(f"{name}: rejected RC={p.returncode} failed={sorted(failed)} red={point}")


RUN = "TestGetComboTypeExhaustive|TestComboRosterMatchesConstants|TestS2aClassifier"
run("positive", PRISTINE, RUN)
cases = [
    ("return_19", PRISTINE.replace("return ComboProtoOnly", "return 19"), "TestGetComboTypeExhaustive_Never19", "那是历史空洞"),
    ("return_40", PRISTINE.replace("return ComboSrcPortOnly", "return 40"), "TestGetComboTypeExhaustive_Never19", "不在名册内"),
    ("retired_20", PRISTINE.replace("return ComboWildcardSrcIPPort", "return 20"), "TestGetComboTypeExhaustive_DeadCombosMatchF072", "S2a 活跃名册应为"),
    ("collapse_outputs", PRISTINE.replace("return ComboDstPortOnly", "return ComboSrcPortOnly"), "TestGetComboTypeExhaustive_Never19", "个不同输入命中"),
    ("constant_drift", re.sub(r"(ComboAllExceptProto\s*=\s*)33", r"\g<1>34", PRISTINE), "TestComboRosterMatchesConstants", "名册写"),
]
for name, source, test, red in cases:
    run(name, source, "^" + test + "$", (test, red))

for function, srcvar, dstvar in [("getComboType", "hasSrcIP", "hasDstIP"), ("getCIDRComboType", "hasSrcID", "hasDstID")]:
    start = PRISTINE.index("func " + function + "(")
    end = PRISTINE.index("\n}", start) + 2
    body = PRISTINE[start:end]
    conditions = re.findall(r"\tcase ([^\n]+):", body)
    def replace_body(mutated):
        assert mutated != body
        return PRISTINE[:start] + mutated + PRISTINE[end:]
    mutations = [
        ("copy_condition", body.replace("case " + conditions[1] + ":", "case " + conditions[0] + ":", 1), "first-hit unreachable"),
        ("shadow_src", body.replace("\tdefault:", f"\tcase {srcvar}:\n\t\treturn 0\n\tdefault:"), "first-hit unreachable"),
        ("shadow_dst", body.replace("\tdefault:", f"\tcase {dstvar}:\n\t\treturn 0\n\tdefault:"), "first-hit unreachable"),
        ("unsatisfiable", body.replace("\tdefault:", f"\tcase {srcvar} && !{srcvar}:\n\t\treturn 0\n\tdefault:"), "unsatisfiable case"),
    ]
    test = "TestS2aClassifierConditions"
    for name, mutated, red in mutations:
        run(function + "_" + name, replace_body(mutated), "^" + test + "$", (test + "/" + function, red))
    swapped = body.replace("return ComboSrcPortOnly", "return TEMP_SWAP").replace("return ComboDstPortOnly", "return ComboSrcPortOnly").replace("return TEMP_SWAP", "return ComboDstPortOnly")
    test = "TestS2aClassifierRosterAndMapping"
    run(function + "_swapped_returns", replace_body(swapped), "^" + test + "$", (test, "field mapping mismatch"))
    for n, symbol in [(20, "ComboWildcardSrcIPPort"), (32, "ComboWildcardSrcIP")]:
        # Matching the trailing newline avoids replacing the longer name.
        mutated = body.replace("return " + symbol + "\n", f"return {n}\n")
        run(function + f"_revive_{n}", replace_body(mutated), "^" + test + "$", (test, "retired/unknown return"))
    test = "TestS2aClassifierConditions"
    mutated = body.replace("hasProto := key.Protocol != 0", "hasProto := key.Protocol == 17")
    run(function + "_new_dependency", replace_body(mutated), "^" + test + "$", (test + "/" + function, "AST derived boolean changed"))

AFTER = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in WATCH}
assert BEFORE == AFTER, "mutation leaked into original API tree"
(WORK / "source-hashes.json").write_text(json.dumps(BEFORE, indent=2) + "\n")
print(f"mutations=21/21 positive=1 original_files_unchanged={len(BEFORE)} artifacts={WORK}")
