#!/usr/bin/env python3
"""Authenticated B0 generator, actual Go/C replay and strict result consumer.

Source roots and contracts are explicit. The instrument root is independent;
its default comes from git show-toplevel, never a resolved script symlink.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

import s2b_cases as cases

PKG='github.com/littlewolf9527/xdrop/node/agent/'
CLASSIFIER_TEST=r'''package api
import("encoding/hex";"encoding/json";"fmt";"os";"testing")
type s2bInputRule struct{ID string;Combo int;WireKey string;Key struct{Src,Dst string;Sport,Dport uint16;Proto uint8};CIDRKey struct{SrcID,DstID uint32;Sport,Dport uint16;Proto uint8}}
func TestS2bGeneratedKeys(t *testing.T){
 raw,err:=os.ReadFile(os.Getenv("S2B_CASE_INPUT"));if err!=nil{t.Fatal(err)}
 var rows []struct{Rules struct{Whitelist,Exact,CIDR []s2bInputRule}}
 if err=json.Unmarshal(raw,&rows);err!=nil{t.Fatal(err)}
 seen:=map[string]bool{};uses:=0;unique:=0
 for _,row:=range rows{for g,rules:=range map[string][]s2bInputRule{"exact":append(row.Rules.Exact,row.Rules.Whitelist...),"cidr":row.Rules.CIDR}{for _,r:=range rules{
  uses++;id:=g+"/"+fmt.Sprint(r.Combo)+"/"+r.WireKey
  if seen[id]{continue};seen[id]=true;unique++
  t.Run(id,func(t *testing.T){var combo int;var wire []byte
   if g=="exact"{
    proto:="all";if r.Key.Proto==6{proto="tcp"}else if r.Key.Proto==17{proto="udp"}else if r.Key.Proto!=0{t.Fatal("unknown protocol")}
    key,err:=(&Handlers{}).ruleToKey(Rule{SrcIP:r.Key.Src,DstIP:r.Key.Dst,SrcPort:r.Key.Sport,DstPort:r.Key.Dport,Protocol:proto});if err!=nil{t.Fatal(err)}
    combo=getComboType(key);wire=ruleKeyToBytes(key)
   }else{
    key:=CIDRRuleKey{SrcID:r.CIDRKey.SrcID,DstID:r.CIDRKey.DstID,SrcPort:htons(r.CIDRKey.Sport),DstPort:htons(r.CIDRKey.Dport),Protocol:r.CIDRKey.Proto}
    combo=getCIDRComboType(key);wire=cidrRuleKeyToBytes(key)
   }
   if combo!=r.Combo{t.Fatalf("actual classifier combo=%d want=%d",combo,r.Combo)}
   if hex.EncodeToString(wire)!=r.WireKey{t.Fatalf("actual API key bytes=%x want=%s",wire,r.WireKey)}
  })
 }}}
 if unique!=64{t.Fatalf("actual unique classifier keys=%d want=64",unique)}
 t.Logf("actual classifier uses=%d unique=%d",uses,unique)
}
'''


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def absolute_root(path):
    path=Path(path)
    if not path.is_absolute():raise cases.CaseError('explicit absolute root required')
    return path.resolve(strict=True)


def write_go_overlay(path,replacements):
    """Use the same physical filenames that Go sees after changing cwd.

    A generated target does not exist yet; its existing parent is canonicalized
    before appending its filename. Never derive a scan root from __file__.
    """
    resolved={}
    for target,source in replacements.items():
        target,source=Path(target),Path(source)
        if not target.is_absolute() or not source.is_absolute():
            raise cases.CaseError('absolute overlay filenames required')
        key=str(target.parent.resolve(strict=True)/target.name)
        if key in resolved:raise cases.CaseError('duplicate canonical overlay target')
        resolved[key]=str(source.resolve(strict=True))
    Path(path).write_text(json.dumps({'Replace':resolved})+'\n')


def load_c(instrument):
    spec=importlib.util.spec_from_file_location('s2b_c_replay',instrument/'node/bpf/tools/s2b_c_replay.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def command(cmd,cwd,stem,env=None):
    p=subprocess.run(list(map(str,cmd)),cwd=cwd,env=env,capture_output=True,text=True)
    stem=Path(stem);stem.parent.mkdir(parents=True,exist_ok=True)
    stem.with_suffix('.stdout').write_text(p.stdout);stem.with_suffix('.stderr').write_text(p.stderr)
    stem.with_suffix('.command.json').write_text(json.dumps({'command':list(map(str,cmd)),'cwd':str(cwd),'rc':p.returncode},indent=2)+'\n')
    return p


def executed(stdout,rc,package,required):
    if rc!=0:raise cases.CaseError(f'test subprocess RC={rc}')
    events=[json.loads(line) for line in stdout.splitlines()]
    if not events:raise cases.CaseError('empty test output')
    bad=[e for e in events if e['Action'] in ('fail','skip')]
    if bad:raise cases.CaseError('test FAIL/SKIP identity: '+str(bad[0]))
    passed=Counter(e['Test'] for e in events if e['Action']=='pass' and e.get('Package')==package and e.get('Test'))
    if set(passed)!=set(required) or any(n!=1 for n in passed.values()):
        raise cases.CaseError(f'executed PASS identity set: actual={len(passed)} expected={len(required)} missing={sorted(set(required)-set(passed))[:3]}')
    if sum(e['Action']=='pass' and e.get('Package')==package and not e.get('Test') for e in events)!=1:raise cases.CaseError('package PASS identity')
    return {'rc':rc,'package':package,'pass':sorted(passed)}


def prepare_inputs(output):
    rows=cases.cases();cases.validate_case_set(rows)
    inp=[]
    for row in rows:
        q=dict(row);q['before_expected']=cases.decision(row,'s2a');q['after_expected']=cases.decision(row,'s2b');inp.append(q)
    path=output/'test-input.json';path.write_text(json.dumps(inp,separators=(',',':'))+'\n')
    return rows,path


def classifier_required(rows):
    keys=set()
    for row in rows:
        for group in ('Whitelist','Exact','CIDR'):
            for rule in row['rules'][group]:keys.add(('cidr' if group=='CIDR' else 'exact',rule['Combo'],rule['WireKey']))
    return {'TestS2bGeneratedKeys'}|{'TestS2bGeneratedKeys/'+g+'/'+str(n)+'/'+wire for g,n,wire in keys}


def expected_execution(output,rows):
    required={'TestS2bCompetition'}|{'TestS2bCompetition/'+'/'.join(cases.identity(row)) for row in rows}
    result={}
    for name,pkg,want in [('evaluator','eval',required),('classifier','api',classifier_required(rows))]:
        meta=json.loads((output/(name+'.command.json')).read_text())
        result[name]=executed((output/(name+'.stdout')).read_text(),meta['rc'],PKG+pkg,want)
    ids=[list(cases.identity(r)) for r in rows if r['c_replay']]
    for side in ('before','after'):
        raw=[json.loads(line) for line in (output/('c-'+side)/'run/stdout.jsonl').read_text().splitlines()]
        rc=int((output/('c-'+side)/'run/rc.txt').read_text())
        if rc or len(raw)!=len(ids):raise cases.CaseError('C required execution identity/count/RC '+side)
        result['c-'+side]={'rc':rc,'identities':ids}
    return result


def consume(output,before,after,instrument,report_path=None):
    before,after,instrument=map(absolute_root,(before,after,instrument))
    sources={'before':cases.source_identity(before,'s2a'),'after':cases.source_identity(after,'s2b')}
    rows=cases.cases();execution=expected_execution(output,rows)
    report=json.loads((report_path or output/'report.json').read_text())
    if type(report) is not dict or set(report)!={'schema','sources','instrument','execution','rows'}:raise cases.CaseError('report schema fields')
    files=instrument_files(instrument)
    if report.get('instrument')!=files:raise cases.CaseError('instrument manifest differs')
    count=cases.validate_report(report,sources,execution)
    # Bind the report to the recorded, actually executed C inputs and outputs.
    # Re-extract the authenticated source through the same strict AST boundary.
    c=load_c(instrument);cr=[r for r in report['rows'] if r['c_replay']]
    generations = {}
    for side,root in [('before',before),('after',after)]:
        directory=output/('c-'+side)
        saved=json.loads((directory/'replay-manifest.json').read_text())
        with tempfile.TemporaryDirectory(prefix='s2b-consume-extract-',dir='/tmp') as tmp:
            unit,defs,expected,_=c.extract(root,Path(tmp))
            generation,shim=c.select_shim(defs)
            expected["interface_generation"]=generation
            expected["shim_sha256"]=c.sha(shim.encode())
            generations[side]=generation
        for key in ('root','source_sha256','unit_sha256','functions','macro_sha256','inputs','interface_generation','shim_sha256'):
            if saved[key]!=expected[key]:raise cases.CaseError('C replay source manifest '+side+'/'+key)
        if (directory/'replay.c').read_bytes()!=unit+shim.encode() or saved['executable_sha256']!=sha(directory/'replay') or int((directory/'build.rc').read_text())!=0:
            raise cases.CaseError('C replay build identity/RC '+side)
        if (directory/'run/stdin.txt').read_text()!=''.join(cases.c_input(r) for r in cr):raise cases.CaseError('C replay input identity '+side)
        raw=[json.loads(line) for line in (directory/'run/stdout.jsonl').read_text().splitlines()]
        if raw!=[r[side+'_c'] for r in cr]:raise cases.CaseError('C raw/report output differs '+side)
    print(json.dumps({'report_rows':count,'pair_identities':len({r['pair_id'] for r in rows if r['pair_id'][0].isdigit()}),
                      'c_rows_each':len(execution['c-before']['identities']),
                      'before_root':sources['before']['root'],'before_commit':sources['before']['source_commit'],
                      'after_root':sources['after']['root'],'after_commit':sources['after']['source_commit'],
                      'interface_generations':generations,'errors':0},sort_keys=True))
    return report


def instrument_files(instrument):
    paths=['node/agent/tools/check_s2b.py','node/agent/tools/s2b_cases.py','node/bpf/tools/s2b_c_replay.py',
           'node/bpf/tools/extract_combo_masks.py','node/agent/eval/testdata/parity/gate-mask-parity.py']
    paths += [str(p.relative_to(instrument)) for p in sorted((instrument/'node/agent/eval').glob('*.go'))]
    return {p:sha(instrument/p) for p in paths}


def run(before,after,output,instrument):
    before,after,instrument=map(absolute_root,(before,after,instrument))
    output.mkdir(parents=True,exist_ok=True)
    output=absolute_root(output)
    sources={'before':cases.source_identity(before,'s2a'),'after':cases.source_identity(after,'s2b')}
    for side,ident in sources.items():print(f"{side} tree={ident['root']} commit={ident['source_commit']} contract={ident['contract']}",flush=True)
    order=cases.check_order_header((after/'node/bpf/combo_masks.h').read_text())
    c=load_c(instrument);c.check_source(after,output/'ast')
    gen=command(['python3',after/'node/bpf/tools/extract_combo_masks.py','--emit-c'],after,output/'generator')
    if gen.returncode or gen.stdout.encode()!=(after/'node/bpf/combo_masks.h').read_bytes():raise cases.CaseError('regenerated header differs or generator failed')
    rows,inp=prepare_inputs(output)
    env=dict(os.environ,GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',TMPDIR='/tmp',S2B_CASE_INPUT=str(inp))
    overlay_source=output/'classifier_test.go';overlay_source.write_text(CLASSIFIER_TEST)
    overlay=output/'overlay.json';write_go_overlay(overlay,{after/'node/agent/api/s2b_generated_test.go':overlay_source})
    p=command(['go','test','-json','-count=1','-overlay',overlay,'./api/','-run','^TestS2bGeneratedKeys$'],after/'node/agent',output/'classifier',env)
    executed(p.stdout,p.returncode,PKG+'api',classifier_required(rows))
    p=command(['go','test','-json','-count=1','./eval/','-run','^TestS2bCompetition$',
               '-eval-instrument-root',instrument,'-s2b-before-root',before,'-s2b-after-root',after,
               '-s2b-input',inp,'-s2b-output',output/'go-actual.json'],after/'node/agent',output/'evaluator',env)
    required={'TestS2bCompetition'}|{'TestS2bCompetition/'+'/'.join(cases.identity(row)) for row in rows}
    executed(p.stdout,p.returncode,PKG+'eval',required)
    go=json.loads((output/'go-actual.json').read_text())
    if type(go) is not list or len(go)!=len(rows):raise cases.CaseError('Go output cardinality/schema')
    for row,actual in zip(rows,go):
        if tuple(actual[k] for k in ('pair_id','stage','variant'))!=cases.identity(row):raise cases.CaseError('Go output identity/order')
        row.update(before_expected=cases.decision(row,'s2a'),before_actual=actual['Before'],after_expected=cases.decision(row,'s2b'),after_actual=actual['After'],before_c=None,after_c=None)
    cr=[q for q in rows if q['c_replay']]
    for side,root,contract in [('before',before,'s2a'),('after',after,'s2b')]:
        binary,record=c.build_replay(root,output/('c-'+side))
        actual=c.run_replay(binary,[cases.c_input(q) for q in cr],output/('c-'+side)/'run')
        for row,one in zip(cr,actual):cases.check_c(row,contract,one);row[side+'_c']=one
    report={'schema':cases.SCHEMA,'sources':sources,'instrument':instrument_files(instrument),'execution':expected_execution(output,rows),'rows':rows}
    (output/'report.json').write_text(json.dumps(report,separators=(',',':'))+'\n')
    return consume(output,before,after,instrument)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--before-root',required=True,type=Path);ap.add_argument('--before-contract',required=True,choices=['s2a'])
    ap.add_argument('--after-root',required=True,type=Path);ap.add_argument('--after-contract',required=True,choices=['s2b'])
    ap.add_argument('--output',required=True,type=Path);ap.add_argument('--instrument-root',type=Path)
    ap.add_argument('--consume',type=Path)
    args=ap.parse_args()
    instrument=args.instrument_root or Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip())
    for p in (args.before_root,args.after_root,args.output,instrument):
        if not p.is_absolute():ap.error('all roots/output must be absolute')
    if args.consume:consume(args.output,args.before_root,args.after_root,instrument,args.consume)
    else:run(args.before_root,args.after_root,args.output,instrument)


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError) as err:
        print('S2B_ERROR: '+str(err),file=sys.stderr);sys.exit(1)
