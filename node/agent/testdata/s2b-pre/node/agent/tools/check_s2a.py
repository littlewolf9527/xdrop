#!/usr/bin/env python3
"""Candidate S2a gate: explicit source identity and exact executed test sets."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

INSTRUMENT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("parity", INSTRUMENT/"internal_docs/plans/phase1/gate-mask-parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root",required=True,type=Path)
    ap.add_argument("--counts",action="store_true")
    args=ap.parse_args()
    if not args.root.is_absolute():ap.error("absolute root required")
    root=args.root.resolve(strict=True)
    report=parity.check(root,"s2a")
    failures=["gate1: "+e["detail"] for e in report["errors"]]
    target=set(range(34))-{19,20,32}
    mask_source=parity.strip_comments((root/"node/bpf/combo_masks.h").read_text())
    header_source=parity.strip_comments((root/"node/bpf/xdrop.h").read_text()).replace("\\\n"," ")
    go_source=(root/"node/agent/api/combo.go").read_text()
    bm=re.findall(r"^#define\s+COMBO_VALID_BITMAP\s+(0x[0-9A-Fa-f]+)ULL\s*$",mask_source,re.M)
    observed_bitmap=int(bm[0],16) if len(bm)==1 else -1
    if observed_bitmap!=sum(1<<n for n in target):failures.append(f"gate1: old/wrong bitmap {observed_bitmap:#x}, want 0x2ffe7ffff")
    c_ids={int(v) for name,v in re.findall(r"^#define\s+(COMBO_\w+)\s+(\d+)\s*$",header_source,re.M) if name!="COMBO_MAX"}
    go_ids={int(v) for name,v in re.findall(r"^\s*(Combo\w+)\s*=\s*(\d+)",go_source,re.M) if name!="ComboBitmapSize"}
    mask_ids={int(i) for i,expr in re.findall(r"\[(\d+)\]\s*=\s*([^,]+),",mask_source) if expr.strip()!="0"}
    for label,ids in [("C",c_ids),("Go",go_ids),("nonzero masks",mask_ids),("gate",set(report["order"]))]:
        if label=="gate" and report["errors"]:continue # A parse failure is already red, not evidence of zero calls.
        if ids!=target:failures.append(f"gate1: {label} set={sorted(ids)} want={sorted(target)}")
    print(f"gate1 measured: C={len(c_ids)} Go={len(go_ids)} nonzero_masks={len(mask_ids)} bitmap={observed_bitmap:#x} gate_calls={report['call_count']}",file=sys.stderr)
    print(json.dumps(report,sort_keys=True),file=sys.stderr)
    env=dict(os.environ,GOPROXY="off",GOSUMDB="off",GOTOOLCHAIN="local",TMPDIR="/tmp")
    cmd=["go","test","-json","-count=1","./api/","./eval/","-run","^TestS2a"]
    p=subprocess.run(cmd,cwd=root/"node/agent",env=env,capture_output=True,text=True)
    print(p.stdout+p.stderr,file=sys.stderr,end="")
    events=[json.loads(line) for line in p.stdout.splitlines()]
    api="github.com/littlewolf9527/xdrop/node/agent/api"
    ev="github.com/littlewolf9527/xdrop/node/agent/eval"
    passed={(e.get("Package"),e.get("Test")) for e in events if e["Action"]=="pass"}
    bad=[e for e in events if e["Action"] in ("fail","skip")]
    if p.returncode or bad:failures.append(f"Go status={p.returncode} fail/skip events={len(bad)}")
    required={(api,t) for t in ["TestS2aClassifierConditions","TestS2aClassifierBeforeAfter","TestS2aClassifierRosterAndMapping"]}
    required|={(ev,t) for t in ["TestS2aEvaluationParity","TestS2aDirtyPinBoundary","TestS2aStrictTableContracts","TestS2aSourceRejections","TestS2aParityCallerIdentity"]}
    required|={(api,"TestS2aClassifierConditions/"+name) for name in ["getComboType","getCIDRComboType"]}
    required|={(ev,"TestS2aParityCallerIdentity/"+name) for name in ["positive","root","contract","authority","hash","path","count","exit"]}
    active=set(range(34))-{19,20,32}
    witnesses={f"TestS2aEvaluationParity/witness-{n}-{s}" for n in active for s in ["whitelist","exact","cidr","anomaly_exact","anomaly_cidr"]}
    fixtures={"fixture-"+s for s in ["1-priority","2-flags","2-length-min","2-length-max","2-length-boundary","2-non-tcp-flags","3-rate-first","4-a","4-b","4-c","5-whitelist","5-exact-before-cidr","5-cidr-before-anomaly-exact","5-anomaly-exact","5-anomaly-cidr","5-none"]}
    comparisons=witnesses|{"TestS2aEvaluationParity/"+s for s in fixtures|{"zero-bitmaps","anomaly-disabled","no-lpm-match"}}
    fields={s+"/"+f for s in comparisons for f in ["Stage","Combo","RuleID","Action"]}
    required|={(ev,s) for s in comparisons|fields}
    boundary={f"TestS2aDirtyPinBoundary/{n}-{s}" for n in [20,32] for s in ["exact","cidr","anomaly_exact","anomaly_cidr"]}
    required|={(ev,s) for s in boundary}
    if required-passed:failures.append("missing executed identities: "+repr(sorted(required-passed)))
    measured={test for package,test in passed if package==ev and test and test.startswith("TestS2aEvaluationParity/") and test.count("/")==1}
    if measured!=comparisons:failures.append("comparison identity set differs")
    if failures:
        print("S2A_ERROR: "+"; ".join(failures))
        return 1
    counts=f"{len(active)}/34/3/64/{len(witnesses)}/{len(comparisons)}/{len(fields)}/{len(boundary)}"
    print(counts if args.counts else "S2a active/slots/holes/classifier_inputs/witnesses/comparisons/fields/dirty="+counts)
    return 0


if __name__=="__main__":
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("S2A_ERROR: "+str(error));sys.exit(1)
