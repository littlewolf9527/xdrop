#!/usr/bin/env python3
"""Run every B0 mutation apparatus positive before enabling any mutants.

All source roots are explicit. The certificate binds the instrument and source
bytes, exact group names and measured identity sets. This is an orchestration
layer only; production C, contracts and the competition specification are read.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode=True
os.environ['PYTHONDONTWRITEBYTECODE']='1'
import check_s2b as gate

SUITES={'c':77,'tables':15,'report':21,'facts':11,'c-order':12,'s4':23}


def fingerprint(root):
    paths=['node/agent/tools/check_s2b.py','node/agent/tools/check_s2b_facts.py',
           'node/agent/tools/mutation_check_s2b.py','node/agent/tools/mutation_check_combo.py','node/agent/tools/check_s2b_apparatus.py',
           'node/agent/tools/s2b_cases.py','node/agent/tools/check_s2a.py',
           'node/bpf/tools/s2b_c_replay.py','node/bpf/tools/test_s2b_c_replay.py',
           'node/bpf/tools/extract_combo_masks.py','node/bpf/tools/test_extract_combo_masks.py',
           'node/agent/eval/testdata/parity/gate-mask-parity.py','node/agent/eval/testdata/parity/test_gate_mask_parity.py',
           'internal_docs/_verify_facts.sh','node/bpf/xdrop_main.c','node/bpf/combo_masks.h','node/bpf/xdrop.h','node/bpf/xdrop_gate.c']
    paths += ['node/agent/api/s4_pkt_attrs_source_test.go']
    paths += [str(p.relative_to(root)) for p in sorted((root/'node/agent/eval').glob('*.go'))]
    return {p:gate.sha(root/p) for p in paths}


def extra_positives(r,out):
    out.mkdir(parents=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',TMPDIR='/tmp')
    rows=[]
    def record(name,p,expected,actual,environment):
     path=out/(name.replace('/','__')+'.log');path.write_text(p.stdout+p.stderr)
     row={'group':name,'environment':environment,'expected_identities':expected,'actual_identities':actual,'expected_count':len(expected),'actual_count':len(actual),'rc':p.returncode,'passed':p.returncode==0 and sorted(expected)==sorted(actual),'log':str(path),'command':list(map(str,p.args))}
     rows.append(row);print(name,row['passed'],len(actual),len(expected),p.returncode,flush=True)
    # Each existing-file overlay is checked by an inert marker in that very
    # replacement file, plus a separate diagnostic test consuming the marker.
    # No contract value or production behavior is changed by this positive probe.
    clone=out/'copy';shutil.copytree(r/'node',clone/'node',ignore=shutil.ignore_patterns('__pycache__'))
    for rel in ['contracts.go','eval_test.go','masks.go']:
     d=out/('overlay-'+rel);d.mkdir();source=d/rel
     marker='s2b_positive_'+rel.replace('.','_')
     source.write_text((clone/'node/agent/eval'/rel).read_text()+'\nconst s2bOverlayPositiveMarker = "'+marker+'"\n')
     probe=d/'probe_test.go';probe.write_text('package eval\nimport "testing"\nfunc TestS2bOverlayPositive(t *testing.T) { if s2bOverlayPositiveMarker != "'+marker+'" { t.Fatal("overlay marker mismatch") } }\n')
     overlay=d/'overlay.json';gate.write_go_overlay(overlay,{clone/'node/agent/eval'/rel:source,clone/'node/agent/eval/s2b_overlay_positive_test.go':probe})
     cmd=['go','test','-json','-count=1','-overlay',str(overlay),'./eval/','-run','^TestS2bOverlayPositive$']
     p=subprocess.run(cmd,cwd=clone/'node/agent',env=env,capture_output=True,text=True)
     events=[json.loads(s) for s in p.stdout.splitlines()];actual=[e['Test'] for e in events if e['Action']=='pass' and e.get('Test')]
     record('GoOverlayCopiedRoot/'+rel,p,['TestS2bOverlayPositive'],actual,str(clone/'node/agent'))
    # Run the real generator mutation driver's baseline function in its own /tmp
    # layout; only definitions are imported (its main mutation function is not run).
    sys.dont_write_bytecode=True;sys.path.insert(0,str(r/'node/agent/tools'))
    spec=importlib.util.spec_from_file_location('gen_test',r/'node/bpf/tools/test_extract_combo_masks.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
    rc,body=g.run(Path(g.SRC).read_text(),Path(g.HDR).read_text(),Path(g.MASK_HDR).read_text(),json.loads(Path(g.BASELINE).read_text()))
    p=subprocess.CompletedProcess(['test_extract_combo_masks.run'],rc,body,'')
    expected=['①','②','③','source-shape','alias','comments']
    actual=[]
    for id_,needle in [('①','✅ ①'),('②','✅ ②'),('③','✅ ③'),('source-shape','✅ post-M1'),('alias','✅ 自检'),('comments','✅ 对撞')]:
     if sum(needle in l for l in body.splitlines())==1:actual.append(id_)
    record('GeneratorHistorical',p,expected,actual,'real test_extract_combo_masks.run /tmp BPF copy')
    # Actual C extraction baseline in the same test class setup, without invoking
    # its unknown-node mutation test method.
    spec=importlib.util.spec_from_file_location('extract_test',r/'node/bpf/tools/test_s2b_c_replay.py');sys.path.insert(0,str(r/'node/bpf/tools'));g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
    g.CExtractionTests.setUpClass();obj=g.CExtractionTests
    unit,defs,record_,_=g.replay.extract(obj.copy,obj.work/'preflight')
    nodes=[n for d in defs for n in g.replay.walk(d) if n['kind']=='UnaryExprOrTypeTraitExpr'];actual=[n['name'] for n in nodes]
    p=subprocess.CompletedProcess(['CExtractionTests.setUpClass','replay.extract'],0,json.dumps(record_), '')
    record('ExtractorUnknownNode',p,['sizeof']*16,actual,str(obj.copy))
    # Parity source positives for all three explicit roots; actual facts caller's
    # positive is covered separately below, with its true child, before any stubs.
    for name,root,contract in [('current',r,'s2b'),('frozen-s2a',r/'node/agent/testdata/s2b-pre','s2a'),('pre-s2a',r/'node/agent/testdata/s2a-pre','pre-s2a')]:
     copyroot=out/('parity-'+name)
     for rel in ['node/bpf/xdrop.h','node/bpf/combo_masks.h','node/bpf/xdrop_gate.c']:
      pth=copyroot/rel;pth.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/rel,pth)
     p=subprocess.run(['python3',str(r/'node/agent/eval/testdata/parity/gate-mask-parity.py'),'--root',str(copyroot),'--contract',contract,'--ck'],env=env,capture_output=True,text=True)
     data=json.loads(p.stderr);actual=data['order'] if p.stdout=='0\n' and not data['errors'] else []
     record('Parity/'+name,p,[i for i in range(34) if i not in [19,20,32]],actual,str(copyroot))
    facts=(r/'internal_docs/_verify_facts.sh').read_text();a=facts.index('s1_parity_count() {');b=facts.index('\n}\n',a)+2
    p=subprocess.run(['bash','-c',facts[a:b]+'\ns1_parity_count'],cwd=r,env=env,capture_output=True,text=True)
    record('ParityActualFactsCaller',p,['0'],p.stdout.strip().splitlines(),str(r))
    # Historical classifier mutation driver uses these actual tests in a full copy.
    cmd=['go','test','-json','-count=1','./api/','-run','TestGetComboTypeExhaustive|TestComboRosterMatchesConstants|TestS2aClassifier']
    p=subprocess.run(cmd,cwd=clone/'node/agent',env=env,capture_output=True,text=True)
    events=[json.loads(s) for s in p.stdout.splitlines()];actual=[e['Test'] for e in events if e['Action']=='pass' and e.get('Test')]
    # Reference comes from the already recorded fixed b07a004 test run, not HEAD.
    expected=['TestGetComboTypeExhaustive_Never19','TestGetComboTypeExhaustive_DeadCombosMatchF072','TestComboRosterMatchesConstants','TestS2aClassifierConditions','TestS2aClassifierConditions/getComboType','TestS2aClassifierConditions/getCIDRComboType','TestS2aClassifierBeforeAfter','TestS2aClassifierRosterAndMapping']
    record('HistoricalClassifier',p,expected,actual,str(clone/'node/agent'))

    # The actual facts caller with its real PATH stub, not merely a direct
    # parser invocation. Each future report corruption shares this baseline.
    fake=out/'fake-python';fake.mkdir()
    parity_tool=r/'node/agent/eval/testdata/parity/gate-mask-parity.py'
    real=subprocess.run([sys.executable,str(parity_tool),'--root',str(r/'node/agent/testdata/s2b-pre'),'--contract','s2a','--ck'],capture_output=True,text=True,env=env)
    positive_report=out/'positive-parity.json';positive_report.write_text(real.stderr)
    stub='#!/bin/sh\ncase "$1" in *gate-mask-parity.py) cat "$S2A_REPORT" >&2; printf \'%s\n\' "$S2A_COUNT"; exit "$S2A_RC";; esac\nexec '+shlex.quote(sys.executable)+' "$@"\n'
    (fake/'python3').write_text(stub);(fake/'python3').chmod(0o700)
    env_stub=dict(env,PATH=str(fake)+os.pathsep+env['PATH'],S2A_REPORT=str(positive_report),S2A_COUNT='0',S2A_RC='0')
    p=subprocess.run(['bash','-c',facts[a:b]+'\ns1_parity_count'],cwd=r,env=env_stub,capture_output=True,text=True)
    record('ParityActualFactsCallerStub',p,['0'],p.stdout.strip().splitlines(),str(fake))
    # The historical caller also consumes an explicit copied source root.
    p=subprocess.run([sys.executable,str(r/'node/agent/tools/check_s2a.py'),'--root',str(clone/'node/agent/testdata/s2b-pre'),'--instrument-root',str(r),'--counts'],cwd=r,env=env,capture_output=True,text=True)
    record('S2aCopiedSource',p,['31/34/3/64/155/174/696/8'],p.stdout.strip().splitlines(),str(clone))
    (out/'preflight.json').write_text(json.dumps(rows,indent=2)+'\n')
    return rows


def selfcheck(root,output,report_dir):
    output.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    def run_suite(suite):
        work=output/suite
        cmd=[sys.executable,str(root/'node/agent/tools/mutation_check_s2b.py'),'--preflight-only',
             '--suite',suite,'--root',str(root),'--instrument',str(root),'--output',str(work)]
        if suite=='report':cmd+=['--report-dir',str(report_dir)]
        p=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True)
        (output/(suite+'.log')).write_text(p.stdout+p.stderr)
        (output/(suite+'.rc')).write_text(str(p.returncode)+'\n')
        rows=json.loads((work/'preflight.json').read_text()) if (work/'preflight.json').exists() else []
        if p.returncode or len(rows)!=SUITES[suite]:
            rows.append({'group':suite+'/setup','environment':str(work),'expected_count':SUITES[suite],
                         'actual_count':len(rows),'rc':p.returncode,'passed':False,'log':str(output/(suite+'.log'))})
        print('GROUP '+suite+' positives='+str(len(rows))+' failures='+str(sum(not x['passed'] for x in rows)),flush=True)
        return rows
    rows=[]
    # Independent processes; no mutation callbacks are called in this phase.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(run_suite,SUITES):rows+=result
    try:rows+=extra_positives(root,output/'other')
    except Exception as error:
        (output/'other-setup.error').write_text(str(error)+'\n')
        rows.append({'group':'other/setup','environment':str(output/'other'),'expected_count':12,'actual_count':0,'rc':1,'passed':False,'error':str(error)})
    names=[x['group'] for x in rows]
    complete=len(rows)==171 and len(set(names))==171 and all(x['passed'] for x in rows)
    result={'schema':'s2b-apparatus-selfcheck-v1','source_root':str(root),'source_commit':'b07a004950e2f813545db540599767e2a4dc214e+working-tree',
            'fingerprint':fingerprint(root),'suite_outputs':{s:str(output/s) for s in SUITES},
            'report_dir':str(report_dir),'rows':rows,'passed':complete,'failure_groups':[x['group'] for x in rows if not x['passed']]}
    (output/'selfcheck.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'positive_groups':len(rows),'failed_groups':result['failure_groups'],'passed':complete}),flush=True)
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--report-dir',required=True,type=Path)
    args=ap.parse_args()
    if any(not p.is_absolute() for p in (args.root,args.output,args.report_dir)):ap.error('absolute paths required')
    result=selfcheck(args.root,args.output,args.report_dir)
    return 0 if result['passed'] else 1


if __name__=='__main__':
    sys.exit(main())
