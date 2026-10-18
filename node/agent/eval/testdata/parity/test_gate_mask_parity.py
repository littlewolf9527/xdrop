#!/usr/bin/env python3
"""Exercise S1-5 contracts and caller identity checks in retained /tmp copies."""
import hashlib
import importlib.util
import json
import os
import shlex
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
TOOL = ROOT / "internal_docs/plans/phase1/gate-mask-parity.py"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("parity", TOOL)
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)
WORK = Path(tempfile.mkdtemp(prefix="s2a-parity-", dir="/tmp"))
WATCH = [ROOT / p for p in parity.INPUTS]
BEFORE = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in WATCH}


def identity(root):
    return {name: {"path": str((root/name).resolve(strict=True)),
                   "sha256": hashlib.sha256((root/name).read_bytes()).hexdigest()}
            for name in parity.INPUTS}


def accept(proc, report, root, contract, expected):
    return (proc.returncode == 0 and proc.stdout == "0\n" and
            report["root"] == str(root.resolve()) and report["inputs"] == expected and
            report["contract"] == contract and report["authority_baseline"] == parity.BASELINE and
            report["call_count"] == 31 and len(report["errors"]) == 0)


def run(name, source, contract, mutate=None, red=None):
    root=WORK/name
    for item in parity.INPUTS:
        dst=root/item; dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/item,dst)
    pristine={item:(root/item).read_bytes() for item in parity.INPUTS}
    command=[sys.executable,str(TOOL),"--root",str(root),"--contract",contract,"--ck"]
    if mutate:
        positive=subprocess.run(command,text=True,capture_output=True)
        (WORK/(name+"-positive.log")).write_text(positive.stdout+positive.stderr)
        assert positive.returncode==0 and positive.stdout=="0\n", ("E6 positive",name,positive.stderr)
        mutate(root)
    try: expected=identity(root)
    except OSError: expected={}
    p=subprocess.run([sys.executable,str(TOOL),"--root",str(root),"--contract",contract,"--ck"],text=True,capture_output=True)
    (WORK/(name+".log")).write_text(p.stdout+p.stderr)
    report=json.loads(p.stderr)
    # Restore even before deciding whether a negative reached its intended red.
    for item,data in pristine.items():(root/item).write_bytes(data)
    restored={item:hashlib.sha256((root/item).read_bytes()).hexdigest() for item in pristine}
    recovered=subprocess.run(command,text=True,capture_output=True) if mutate else None
    if mutate:
        (WORK/(name+"-recovered.log")).write_text(recovered.stdout+recovered.stderr)
        assert recovered.returncode==0 and recovered.stdout=="0\n", ("E6 recovery",name,recovered.stderr)
    record={"test":"parity/"+name,"expected_red":red,"actual_red":report["errors"],"rc":p.returncode,"restored_sha256":restored,"positive_rc":positive.returncode if mutate else None,"recovered_rc":recovered.returncode if mutate else None}
    (WORK/(name+"-evidence.json")).write_text(json.dumps(record,indent=2)+"\n")
    count=int(p.stdout)
    assert count==len(report["errors"]),(name,p.stdout,report)
    if red:
        assert p.returncode!=0 and count>0 and any(red in e["detail"] for e in report["errors"]),(name,report)
        print(f"{name}: rejected violations={count} RC={p.returncode} red={report['errors']}")
    else:
        assert accept(p,report,root,contract,expected),(name,report)
        print(f"{name}: calls={report['call_count']} violations=0 RC=0 identity=PASS")
    return p,report,root,expected


def replace(file,old,new):
    def mutation(root):
        p=root/file; s=p.read_text(); assert old in s and old!=new
        p.write_text(s.replace(old,new,1))
    return mutation


positive=run("current",ROOT,"s2b")
run("frozen-s2a",ROOT/"node/agent/testdata/s2b-pre","s2a")
run("historical",ROOT/"node/agent/testdata/s2a-pre","pre-s2a")
cases=[
 ("missing-source",lambda root:(root/"node/bpf/xdrop_gate.c").rename(root/"gate.absent"),"No such file"),
 ("wrong-bitmap",replace("node/bpf/combo_masks.h","0x00000002FFE7FFFFULL","0x00000003FFF7FFFFULL"),"valid bitmap"),
 ("nonzero-retired",replace("node/bpf/combo_masks.h","[20] = 0","[20] = CM_DST_IP"),"AUTH vs combo_masks.h mismatch at combo 20"),
 ("wrong-mask",replace("node/bpf/combo_masks.h","[0] = CM_SRC_IP |", "[0] ="),"AUTH vs combo_masks.h mismatch at combo 0"),
 ("wrong-source",replace("node/bpf/xdrop_gate.c","ip_copy(&lookup.src_ip, &key.src_ip)","ip_copy(&lookup.src_ip, &key.dst_ip)"),"source='dst_ip'"),
 ("unknown-syntax",replace("node/bpf/xdrop_gate.c","lookup.src_port = key.src_port","lookup.src_port = key.src_port + 0"),"unknown statement/expression"),
 ("missing-assignment",replace("node/bpf/xdrop_gate.c","lookup.src_port = key.src_port;", ""),"missing fields"),
 ("unknown-call",replace("node/bpf/xdrop_gate.c","WL_COMBO_CHECK(COMBO_EXACT_5TUPLE,", "WL_COMBO_CHECK(COMBO_UNKNOWN,"),"unknown combo symbol"),
 ("unparsed-call",replace("node/bpf/xdrop_gate.c","WL_COMBO_CHECK(COMBO_EXACT_5TUPLE,", "WL_COMBO_CHECK(0,"),"unparsed WL_COMBO_CHECK invocation"),
]


def reorder(root):
    p=root/"node/bpf/xdrop_gate.c";s=p.read_text()
    calls=list(re.finditer(r"WL_COMBO_CHECK\(COMBO_\w+,\s*\{[^{}]*\}\)",s,re.S))
    assert len(calls)==31
    a,b=calls[:2]
    p.write_text(s[:a.start()]+b[0]+s[a.end():b.start()]+a[0]+s[b.end():])


def duplicate(root):
    p=root/"node/bpf/xdrop_gate.c";s=p.read_text()
    m=re.search(r"WL_COMBO_CHECK\(COMBO_\w+,\s*\{[^{}]*\}\)",s,re.S);assert m
    p.write_text(s[:m.end()]+"\n"+m[0]+s[m.end():])


cases += [("wrong-order",reorder,"source order is not ascending"),("duplicate-call",duplicate,"duplicate combo indices")]
for name,mut,red in cases:run(name,ROOT,"s2b",mut,red)
run("old-as-new",ROOT/"node/agent/testdata/s2a-pre","s2a",red="roster differs")
run("new-as-old",ROOT,"pre-s2a",red="roster differs")

# The child may be green yet report the wrong input. Exercise caller checks,
# retaining a valid report as the positive control for each single corruption.
p,report,root,expected=positive
for name,mutate in [
 ("wrong-root",lambda r:r.update(root=str(root.parent))),
 ("wrong-hash",lambda r:r["inputs"][parity.INPUTS[0]].update(sha256="0"*64)),
 ("wrong-path",lambda r:r["inputs"][parity.INPUTS[0]].update(path=str(root/"wrong.h"))),
 ("wrong-contract",lambda r:r.update(contract="pre-s2a")),
 ("wrong-authority",lambda r:r.update(authority_baseline="0"*40)),
]:
    altered=json.loads(json.dumps(report));mutate(altered)
    assert accept(p,report,root,"s2b",expected), "positive caller changed"
    assert not accept(p,altered,root,"s2b",expected),name
    restored_report=json.loads(json.dumps(report))
    assert accept(p,restored_report,root,"s2b",expected)
    (WORK/("caller-"+name+"-evidence.json")).write_text(json.dumps({
        "test":"accept/"+name,"expected_red":"identity rejected","actual_red":"accept=False",
        "rc":None,"result":False,"child_rc":p.returncode,
        "restored_sha256":{"report":hashlib.sha256(json.dumps(restored_report,sort_keys=True).encode()).hexdigest()},
        "recovered_result":True},indent=2)+"\n")
    print(f"caller-{name}: rejected identity; positive violations=0 RC=0")

# Execute the actual facts caller function, with only its child report replaced.
# The outer Python interpreter still runs the repository's real validation code.
facts=(ROOT/"internal_docs/_verify_facts.sh").read_text()
start=facts.index("s1_parity_count() {");end=facts.index("\n}\n",start)+2
function=facts[start:end]
fake=WORK/"fake-python";fake.mkdir()
stub=("#!/bin/sh\ncase \"$1\" in *gate-mask-parity.py) cat \"$S2A_REPORT\" >&2; printf '%s\\n' \"$S2A_COUNT\"; exit \"$S2A_RC\";; esac\nexec "+shlex.quote(sys.executable)+" \"$@\"\n")
(fake/"python3").write_text(stub);(fake/"python3").chmod(0o700)
real=parity.check(ROOT/"node/agent/testdata/s2b-pre","s2a")
for name,mutate,count,rc in [
 ("positive",lambda r:None,"0","0"),
 ("root",lambda r:r.update(root="/tmp/wrong"),"0","0"),
 ("hash",lambda r:r["inputs"][parity.INPUTS[0]].update(sha256="wrong"),"0","0"),
 ("path",lambda r:r["inputs"][parity.INPUTS[0]].update(path="/tmp/wrong.h"),"0","0"),
 ("authority",lambda r:r.update(authority_baseline="wrong"),"0","0"),
 ("contract",lambda r:r.update(contract="pre-s2a"),"0","0"),
 ("count",lambda r:None,"1","0"),
 ("exit",lambda r:None,"0","1"),
]:
    r=json.loads(json.dumps(real));mutate(r);path=WORK/("facts-"+name+".json");path.write_text(json.dumps(r))
    env=dict(os.environ,PATH=str(fake)+os.pathsep+os.environ["PATH"],S2A_REPORT=str(path),S2A_COUNT=count,S2A_RC=rc)
    p=subprocess.run(["bash","-c",function+"\ns1_parity_count"],cwd=ROOT,env=env,text=True,capture_output=True)
    (WORK/("facts-"+name+".log")).write_text(p.stdout+p.stderr)
    path.write_text(json.dumps(real))
    restored=hashlib.sha256(path.read_bytes()).hexdigest()
    restored_env=dict(env,S2A_COUNT="0",S2A_RC="0")
    recovered=subprocess.run(["bash","-c",function+"\ns1_parity_count"],cwd=ROOT,env=restored_env,text=True,capture_output=True)
    (WORK/("facts-"+name+"-recovered.log")).write_text(recovered.stdout+recovered.stderr)
    assert recovered.returncode==0 and recovered.stdout=="0\n",("E6 recovery",name,recovered.stdout,recovered.stderr)
    (WORK/("facts-"+name+"-evidence.json")).write_text(json.dumps({
        "test":"s1_parity_count/"+name,"expected_red":"PARITY_ERROR" if name!="positive" else None,
        "actual_red":p.stdout.strip(),"rc":p.returncode,"recovered_rc":recovered.returncode,
        "restored_sha256":{"report":restored},"log":str(WORK/("facts-"+name+".log"))},indent=2)+"\n")
    if name=="positive":assert p.returncode==0 and p.stdout=="0\n",(name,p.stdout,p.stderr)
    else:assert p.returncode!=0 and "PARITY_ERROR" in p.stdout,(name,p.stdout,p.stderr)
    print(f"actual-facts-caller-{name}: RC={p.returncode} body={p.stdout.strip()}")
print("actual_facts_caller positive=1 rejections=7")

assert BEFORE=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in WATCH},"mutation leaked"
print(f"parity positives=3 semantic_rejections={len(cases)+2} identity_rejections=5 original_files_unchanged=3 artifacts={WORK}")
