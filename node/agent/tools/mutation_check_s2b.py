#!/usr/bin/env python3
"""B0 targeted mutants; every source mutation is retained under /tmp.

A wrong red stops immediately (E6). Normal compilation/identity failures are
never credited as runtime C behavior. The worker calls the production replay
consumer, not a parallel assertion implementation.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import s2b_cases as cases
import check_s2b as gate


# Preflight records use the very same run closures and source copies as mutants.
# No mutate callback is invoked while collecting all positive failures.
PREFLIGHT_ONLY = False
PREFLIGHT_CACHE = {}


def positive_identity(name, p):
    clean = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout)
    if name.startswith(('CReplay/', 'COrder/', 'S4/')):
        expected = ['actual test ' + name + ' passed']
        actual = [s for s in clean.splitlines() if s.startswith('actual test ')]
    elif name.startswith('TestS2b'):
        test = 'TestS2bSourceProbe' if name.startswith('TestS2bSourceProbe/') else name
        expected = [test] if '/' not in test else [test.split('/')[0], test]
        actual = re.findall(r'^\s*--- PASS: (\S+) \(', clean, re.M)
    elif name.startswith('ReportConsumer/'):
        expected = [25753, 465, 25247]
        reports = [json.loads(line) for line in clean.splitlines() if line.startswith('{')]
        actual = [reports[0][k] for k in ('report_rows', 'pair_identities', 'c_rows_each')] if len(reports) == 1 else []
    elif name.startswith('DependencyIsolation/'):
        expected = ['0/1']; actual = clean.strip().splitlines()
    elif name.startswith('FactsInventory/'):
        expected = ['1']; actual = clean.strip().splitlines()
    elif name.startswith('FactsPrune/'):
        expected = ['F-008:0']; actual = ['F-008:0' for line in clean.splitlines() if re.fullmatch(r'\s*✓\s+F-008\s+regular\s+0', line)]
    elif name.startswith('FactsB0/'):
        expected = ['31/465/25753/25247/4/0']; actual = clean.strip().splitlines()
    else:
        raise ValueError('unregistered preflight identity ' + name)
    return expected, actual


def record_preflight(work, name, p, directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'preflight.log').write_text(p.stdout+p.stderr)
    expected,actual=positive_identity(name,p)
    row={'group':name,'environment':str(directory),'command':list(map(str,p.args)) if isinstance(p.args,list) else p.args,
         'expected_identities':expected,'actual_identities':actual,'expected_count':len(expected),'actual_count':len(actual),
         'rc':p.returncode,'passed':p.returncode==0 and sorted(actual)==sorted(expected),
         'log':str(directory/'preflight.log')}
    if name.startswith('FactsB0/'):
        paths=re.findall(r'"output": "([^"]+)"',p.stderr)
        if len(paths)==1:
            out=Path(paths[0]);events=[json.loads(line) for line in (out/'classifier.stdout').read_text().splitlines()]
            got=[e['Test'] for e in events if e['Action']=='pass' and e.get('Test')]
            row['classifier_expected_count']=65;row['classifier_actual_count']=len(got);row['classifier_output']=str(out/'classifier.stdout')
            row['passed'] &= len(got)==65 and len(set(got))==65
    path=work/'preflight.json';rows=json.loads(path.read_text()) if path.exists() else []
    rows.append(row);path.write_text(json.dumps(rows,indent=2)+'\n')
    print('PREFLIGHT '+json.dumps(row),flush=True)
    return row


MD5_READS = {}


def digest(path):
    data = Path(path).read_bytes()
    MD5_READS[str(Path(path).resolve())] = hashlib.md5(data).hexdigest()
    return hashlib.sha256(data).hexdigest()


def worker(args):
    c=gate.load_c(args.instrument)
    if args.mode=='static':c.check_source(args.root,args.output)
    elif args.mode=='widths':c.check_attrs_widths(args.root,args.output)
    elif args.mode=='symbols':c.check_old_symbols(args.root)
    elif args.mode=='callers':
        from check_s2b_facts import s4_callers
        s4_callers(args.root,args.instrument)
    else:
        payload=json.loads(args.input.read_text());row=payload['row'];options=payload['options']
        binary,_=c.build_replay(args.root,args.output)
        result=c.run_replay(binary,[cases.c_input(row,**options)],args.output/'run')[0]
        checkopts=dict(options)
        cases.check_c(row,payload.get('contract','s2b'),result,**checkopts)
    print('actual test '+args.test_id+' passed')


def function_mutation(source,name,transform):
    hits=list(re.finditer(r'^static[^;{}]*\b'+name+r'\s*\([^;{}]*\)\s*\{',source,re.M))
    if len(hits)!=1:raise RuntimeError('mutation function identity not unique: '+name)
    a=hits[0].start();b=hits[0].end();depth=1
    while depth:
        depth+=(source[b]=='{')-(source[b]=='}');b+=1
    original=source[a:b];altered=transform(original)
    if original==altered:raise RuntimeError('empty mutation '+name)
    return source[:a]+altered+source[b:]


def replace_once(old,new):
    def f(s):
        if s.count(old)!=1:raise RuntimeError('mutation anchor count '+repr(old)+'='+str(s.count(old)))
        return s.replace(old,new,1)
    return f


def c_mutations(root,work,instrument):
    c=gate.load_c(instrument)
    pristine={p:(root/p).read_bytes() for p in ('node/bpf/xdrop_main.c','node/bpf/xdrop.h','node/bpf/combo_masks.h','node/bpf/xdrop_gate.c','node/bpf/headers/bpf_helpers.h')}
    source=pristine['node/bpf/xdrop_main.c'].decode()
    definitions=[]
    stage_for={'lookup_rule':'exact','lookup_rule_anomaly':'anomaly_exact','lookup_cidr_rule':'cidr','lookup_cidr_rule_anomaly':'anomaly_cidr'}
    for fn,stage in stage_for.items():
        normal=cases.make_case(5,24,stage,'dual')
        def add(label,transform,red='C probe/key trajectory',mode='runtime',row=None,options=None,header=None):
            definitions.append((fn+'/'+label,function_mutation(source,fn,transform),red,mode,row or normal,options or {},header))
        add('numbered-id',replace_once('__u32 b = combo_order[i];','__u32 b = i;'))
        add('overwrite-id',replace_once('__u32 b = combo_order[i];','__u32 b = combo_order[i];\n    b = i;'))
        add('bitmap-position',replace_once('bitmap & (1ULL << b)','bitmap & (1ULL << i)'))
        builder='build_cidr_rule_key' if 'cidr' in fn else 'build_rule_key'
        add('builder-position',replace_once(builder+'(matched_key, key, b);',builder+'(matched_key, key, i);'))
        tail=cases.make_case(8,8,stage,'single-a');tail['pair_id']='tail-8'
        add('short-bound',replace_once('bpf_iter_num_new(&iter, 0, COMBO_ORDER_LEN);','bpf_iter_num_new(&iter, 0, COMBO_ORDER_LEN - 1);'),row=tail)
        add('early-break',replace_once('__u32 i = (__u32)*pos;','break;\n    __u32 i = (__u32)*pos;'),row=tail)
        add('missing-destroy',replace_once('bpf_iter_num_destroy(&iter);',''),red='C destroy path')
        add('bitmap-miss-continue',replace_once('if (!(bitmap & (1ULL << b)))\n      continue;','if (!(bitmap & (1ULL << b))) ;'),row=cases.make_case(5,24,stage,'bitmap-a'))
        failed=cases.make_case(8,8,stage,'single-a');failed['pair_id']='failed-tail-8';failed['rules'][cases.group(stage)][0]['MinLength']=65
        add('failed-predicate-stale-rule',replace_once('    rule = NULL;','    ;'),red='C winner',row=failed)
        add('valid-filter',replace_once('bitmap &= COMBO_VALID_BITMAP;',';'),red='C valid bitmap filter',mode='static')
        for label,old,new,red in [
            ('empty-i-guard','if (i >= COMBO_ORDER_LEN)\n      break;','if (i >= COMBO_ORDER_LEN) ;','C position dominating guard'),
            ('empty-b-guard','if (b >= COMBO_MAX)\n      break;','if (b >= COMBO_MAX) ;','C combo dominating guard'),
            ('bypassed-i-guard','if (i >= COMBO_ORDER_LEN)','if (i >= COMBO_ORDER_LEN && 0)','C position dominating guard'),
            ('bypassed-b-guard','if (b >= COMBO_MAX)','if (b >= COMBO_MAX && 0)','C combo dominating guard'),
            ('late-i-guard','if (i >= COMBO_ORDER_LEN)\n      break;\n    __u32 b = combo_order[i];','__u32 b = combo_order[i];\n    if (i >= COMBO_ORDER_LEN)\n      break;','C position dominating guard'),
            ('late-b-guard','if (b >= COMBO_MAX)\n      break;\n    if (!(bitmap & (1ULL << b)))\n      continue;','if (!(bitmap & (1ULL << b)))\n      continue;\n    if (b >= COMBO_MAX)\n      break;','C combo dominating guard'),
        ]:add(label,replace_once(old,new),red,mode='static')
        # These are explicitly low-level safety probes, never normal RuleSets.
        for pos in (-1,31):
            add('unsafe-position-'+str(pos),replace_once('if (i >= COMBO_ORDER_LEN)\n      break;',';'),red='runtime error: index',options={'override':pos})
        header=pristine['node/bpf/combo_masks.h'].decode().replace('    0, 1, 22,','    64, 1, 22,',1)
        if header==pristine['node/bpf/combo_masks.h'].decode():raise RuntimeError('guard probe header anchor absent')
        add('unsafe-combo-shift',replace_once('if (b >= COMBO_MAX)\n      break;',';'),red='runtime error: shift exponent 64',options={'override':0},header=header)
    definitions.append(('builders/mask-index',source.replace('combo_field_mask[(combo)]','combo_field_mask[0]',1),'C probe/key trajectory','runtime',cases.make_case(5,24,'exact','dual'),{},None))
    results=[]
    for name,mutant,red,mode,row,options,header in definitions:
        directory=work/name.replace('/','__');directory.mkdir(parents=True,exist_ok=True)
        target=directory/'source'
        for rel,data in pristine.items():
            p=target/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        if header is not None and not PREFLIGHT_ONLY:(target/'node/bpf/combo_masks.h').write_text(header)
        inp=directory/'input.json';inp.write_text(json.dumps({'row':row,'options':{} if PREFLIGHT_ONLY and header is not None else options})+'\n')
        def run(label):
            cmd=[sys.executable,str(instrument/'node/agent/tools/mutation_check_s2b.py'),'--worker','--mode',mode,'--root',str(target),'--instrument',str(instrument),'--output',str(directory/label),'--test-id','CReplay/'+name]
            if mode=='runtime':cmd+=['--input',str(inp)]
            p=subprocess.run(cmd,cwd=instrument,capture_output=True,text=True)
            (directory/(label+'.log')).write_text(p.stdout+p.stderr)
            return p
        positive=run('positive')
        if PREFLIGHT_ONLY:
            record_preflight(work,'CReplay/'+name,positive,directory)
            continue
        if positive.returncode:raise RuntimeError('E6: positive failed '+name+' '+positive.stderr)
        (target/'node/bpf/xdrop_main.c').write_text(mutant)
        try:
            cases.source_identity(target,'s2b')
        except cases.CaseError as error:
            if 'source identity' not in str(error):raise RuntimeError('E6 unrelated identity rejection: '+str(error))
            (directory/'identity-rejection.json').write_text(json.dumps({'rc':1,'error':str(error)})+'\n')
        else:raise RuntimeError('mutant source identity accepted')
        negative=run('mutant');output=negative.stdout+negative.stderr
        # Always restore before deciding whether to stop.
        for rel,data in pristine.items():(target/rel).write_bytes(data)
        restored={rel:digest(target/rel) for rel in pristine}
        if restored!={rel:hashlib.sha256(data).hexdigest() for rel,data in pristine.items()}:raise RuntimeError('restoration drift')
        restored_md5={rel:hashlib.md5((target/rel).read_bytes()).hexdigest() for rel in pristine}
        if restored_md5!={rel:hashlib.md5(data).hexdigest() for rel,data in pristine.items()}:raise RuntimeError('restoration MD5 drift')
        print('RESTORATION '+json.dumps({'test':'CReplay/'+name,'md5':restored_md5}),flush=True)
        if header is not None:(target/'node/bpf/combo_masks.h').write_text(header)
        recovered=run('recovered')
        for rel,data in pristine.items():(target/rel).write_bytes(data)
        if any(hashlib.md5((target/rel).read_bytes()).digest()!=hashlib.md5(data).digest() for rel,data in pristine.items()):raise RuntimeError('recovered restoration MD5 drift')
        row_record={'restored_md5':restored_md5,'test':'CReplay/'+name,'description':name,'mode':mode,'expected_red':red,'actual_red':next((line for line in output.splitlines() if red in line),output),
                    'rc':negative.returncode,'positive_rc':positive.returncode,'recovered_rc':recovered.returncode,'restored_sha256':restored,'artifacts':str(directory)}
        results.append(row_record);(work/'matrix.json').write_text(json.dumps(results,indent=2)+'\n')
        if negative.returncode==0 or red not in output or 'compilation failed' in output or 'E1:' in output or recovered.returncode:
            raise RuntimeError('E6: uncovered or wrong red '+name+' '+output)
        print(json.dumps(row_record),flush=True)
    if any(digest(root/rel)!=hashlib.sha256(data).hexdigest() for rel,data in pristine.items()):raise RuntimeError('original tree drift')
    return results


def record_trial(work, name, run, mutate, restore, expected, mode='semantic'):
    directory=work/name
    if PREFLIGHT_ONLY:
        try:
            directory.mkdir(parents=True,exist_ok=True)
            if run not in PREFLIGHT_CACHE:
                PREFLIGHT_CACHE[run]=run()
            positive=PREFLIGHT_CACHE[run]
        except Exception as error:
            positive=subprocess.CompletedProcess(['prepare',str(directory)],1,'',str(error)+'\n')
        record_preflight(work,name,positive,directory)
        return
    directory.mkdir(parents=True,exist_ok=True)
    def call(label):
        p=run();(directory/(label+'.log')).write_text(p.stdout+p.stderr)
        return p
    MD5_READS.clear()
    original_hashes=restore(); original_md5=dict(MD5_READS)
    positive=call('positive')
    if positive.returncode:raise RuntimeError('E6: positive failed '+name+' '+positive.stdout+positive.stderr)
    mutate();negative=call('mutant');out=negative.stdout+negative.stderr
    restored=restore()
    if restored!=original_hashes or any(hashlib.md5(Path(p).read_bytes()).hexdigest()!=h for p,h in original_md5.items()):
        raise RuntimeError('restoration MD5/SHA drift: '+name)
    print('RESTORATION '+json.dumps({'test':name,'md5':original_md5}),flush=True)
    recovered=call('recovered')
    result={'test':name,'description':name,'mode':mode,'expected_red':expected,
            'actual_red':next((line.strip() for line in out.splitlines() if expected in line),out),
            'rc':negative.returncode,'positive_rc':positive.returncode,'recovered_rc':recovered.returncode,
            'restored_sha256':restored,'restored_md5':original_md5,'artifacts':str(directory)}
    path=work/'matrix.json';rows=json.loads(path.read_text()) if path.exists() else []
    rows.append(result);path.write_text(json.dumps(rows,indent=2)+'\n')
    if negative.returncode==0 or expected not in out or recovered.returncode or '[build failed]' in out or 'E1:' in out:
        raise RuntimeError('E6: uncovered or wrong red '+name+' '+out)
    print(json.dumps(result),flush=True)


def table_mutations(root,work,instrument):
    target=work/'source'
    paths=('node/bpf/xdrop.h','node/bpf/combo_masks.h','node/bpf/xdrop_gate.c')
    pristine={n:(root/n).read_bytes() for n in paths}
    for n,b in pristine.items():p=target/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
    header=pristine[paths[1]].decode();order=cases.check_order_header(header)
    env=dict(os.environ,GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',TMPDIR='/tmp')
    binary=work/'eval.test'
    p=subprocess.run(['go','test','-c','-o',str(binary),'./eval/'],cwd=root/'node/agent',env=env,capture_output=True,text=True)
    (work/'build.log').write_text(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError('E6: test build failed '+p.stderr)
    def run():return subprocess.run([str(binary),'-test.v','-test.run','^TestS2bSourceProbe$',
            '-s2b-after-root',str(target),'-eval-instrument-root',str(instrument)],cwd=root/'node/agent',env=env,capture_output=True,text=True)
    def restore():
        for n,b in pristine.items():(target/n).write_bytes(b)
        return {n:digest(target/n) for n in paths}
    def neworder(values):return re.sub(r'(static const __u8 combo_order\[\] = \{)[^{}]*(\};)',lambda m:m[1]+'\n    '+', '.join(map(str,values))+',\n'+m[2],header)
    defs=[('numbered',list(cases.ACTIVE),'s2b K order'),('tie',[order[0],order[2],order[1]]+order[3:],'s2b K order'),
          ('missing',order[:-1],'order missing valid entries'),('duplicate',[order[0]]+order[:-1],'out of range/absent/duplicate')]
    for name,n in [('retired',20),('negative',-1),('combo-max',34),('shift-width',64)]:defs.append((name,[n]+order[1:],'out of range/absent/duplicate'))
    texts=[(name,neworder(values),red) for name,values,red in defs]
    texts += [('unknown-syntax',neworder(['mystery']+order[1:]),'unknown s2b order syntax'),
              ('missing-length',header.replace('#define COMBO_ORDER_LEN (sizeof(combo_order) / sizeof(combo_order[0]))',''),'s2b order length must use actual sizeof'),
              ('duplicate-table',header+'\nstatic const __u8 combo_order[] = {0,};\n','s2b order definitions must be exactly one')]
    for name,text_,red in texts:
        record_trial(work,'TestS2bSourceProbe/'+name,run,lambda s=text_:(target/paths[1]).write_text(s),restore,red,'source semantic rejection')
    gate_source=pristine[paths[2]].decode();hits=list(re.finditer(r'WL_COMBO_CHECK\(COMBO_\w+,\s*\{[^{}]*\}\)',gate_source,re.S))
    if len(hits)!=31:raise RuntimeError('whitelist mutation identities')
    a,b=hits[:2];mutated=gate_source[:a.start()]+b[0]+gate_source[a.end():b.start()]+a[0]+gate_source[b.end():]
    record_trial(work,'TestS2bSourceProbe/whitelist',run,lambda:(target/paths[2]).write_text(mutated),restore,'whitelist order','source semantic rejection')
    overlays=[
        ('TestS2bFrozenContracts','node/agent/eval/contracts.go',
         lambda s:replace_once('0246f4655ea2cad3adfa958112a6db800d05705064efc634a5360796e92318f5','89bc86b42bb261c580935d81e0f92e82cae29b4cc2278020932e554513e25cd0')(s),'frozen s2a contract hashes changed'),
        ('TestS2bHistoricalRouting','node/agent/eval/eval_test.go',
         replace_once('return filepath.Join(root, "node/agent/testdata/s2b-pre")','return root'),'S2a must use frozen before root'),
        ('TestS2bCrossedSources/unknown','node/agent/eval/masks.go',
         replace_once('t := Tables{contract: contract}','if contract == "unknown" { contract = S2b }; t := Tables{contract: contract}'),'crossed/unknown source accepted'),
    ]
    for name,rel,transform,red in overlays:
        copied=work/(name.replace('/','-')+'.go');original=(root/rel).read_bytes();copied.write_bytes(original)
        overlay=work/(name.replace('/','-')+'.overlay.json');gate.write_go_overlay(overlay,{root/rel:copied})
        def run():return subprocess.run(['go','test','-count=1','-v','-overlay',str(overlay),'./eval/','-run','^'+name.replace('/','$/^')+'$',
                  '-eval-instrument-root',str(instrument),'-eval-contract','s2a'],cwd=root/'node/agent',env=env,capture_output=True,text=True)
        def restore():copied.write_bytes(original);return {str(copied):digest(copied),rel:digest(root/rel)}
        record_trial(work,name,run,lambda:copied.write_text(transform(original.decode())),restore,red)
    if any(digest(root/n)!=hashlib.sha256(b).hexdigest() for n,b in pristine.items()):raise RuntimeError('original source drift')


def report_mutations(root,work,instrument,original):
    # Copy only report inputs, not compiled source/build trees. Those are read-only.
    # Every modified artifact below lives under this /tmp copy.
    target=work/'result';shutil.copytree(original,target,dirs_exist_ok=True)
    path=target/'report.json';pristine=path.read_bytes();report=json.loads(pristine)
    anchor=[i for i,r in enumerate(report['rows']) if cases.identity(r)==('anchor','exact','1-priority')]
    if len(anchor)!=1:raise RuntimeError('anchor positive identity count')
    ai=anchor[0]
    def run():return subprocess.run([sys.executable,str(instrument/'node/agent/tools/check_s2b.py'),
        '--before-root',str(root/'node/agent/testdata/s2b-pre'),'--before-contract','s2a',
        '--after-root',str(root),'--after-contract','s2b','--instrument-root',str(instrument),
        '--output',str(target),'--consume',str(path)],cwd=root,capture_output=True,text=True)
    def rewrite(fn):
        obj=json.loads(pristine);fn(obj);path.write_text(json.dumps(obj,separators=(',',':'))+'\n')
    def restore():path.write_bytes(pristine);return {'report.json':digest(path)}
    defs=[
        ('missing-pair',lambda o:o.update(rows=[r for r in o['rows'] if r['pair_id']!='00-01']),'case identity set differs'),
        ('missing-stage',lambda o:o.update(rows=[r for r in o['rows'] if r['stage']!='anomaly_cidr']),'case identity set differs'),
        ('duplicate-fill',lambda o:o['rows'].__setitem__(1,o['rows'][0]),'duplicate case identity'),
        ('same-key',lambda o:o['rows'][0]['rules']['Exact'][1].update(Key=o['rows'][0]['rules']['Exact'][0]['Key'],WireKey=o['rows'][0]['rules']['Exact'][0]['WireKey']),'case specification differs'),
        ('candidate-absent',lambda o:o['rows'][ai]['rules']['Exact'].pop(),'case specification differs'),
        ('old-winner-both-columns',lambda o:o['rows'][ai].update(after_expected=o['rows'][ai]['before_actual'],after_actual=o['rows'][ai]['before_actual']),"after_expected.Combo: 5 != 24"),
        ('actual-copied-to-expected',lambda o:o['rows'][ai].update(after_expected=dict(o['rows'][ai]['after_actual'],RuleID='fabricated'),after_actual=dict(o['rows'][ai]['after_actual'],RuleID='fabricated')),"after_expected.RuleID: 'fabricated' != 'fine-rate'"),
        ('missing-output-field',lambda o:o['rows'][ai].pop('after_actual'),'report row fields'),
        ('rows-dict',lambda o:o.update(rows={}),'report rows must be list'),
        ('empty-report',lambda o:o.clear(),'report schema fields'),
        ('unknown-schema',lambda o:o.update(schema='unknown'),'unknown report schema'),
        ('wrong-source',lambda o:o['sources']['after'].update(root='/tmp/other-source'),'report source identity'),
        ('wrong-field-type',lambda o:o['rows'][ai]['after_actual'].update(Combo='24'),'Decision schema/type'),
        ('skip-c-report',lambda o:o['execution'].pop('c-after'),'report execution identities/RC'),
    ]
    for name,mut,red in defs:record_trial(work,'ReportConsumer/'+name,run,lambda:rewrite(mut),restore,red)
    def rawtrial(name,rel,transform,red):
        p=target/rel;data=p.read_bytes()
        def restore_raw():p.write_bytes(data);return {rel:digest(p),'report.json':digest(path)}
        record_trial(work,'ReportConsumer/'+name,run,lambda:p.write_bytes(transform(data)),restore_raw,red)
    def jsonmut(fn):
        def f(data):o=json.loads(data);fn(o);return (json.dumps(o)+'\n').encode()
        return f
    rawtrial('valid-stdout-failed-rc','evaluator.command.json',jsonmut(lambda o:o.update(rc=17)),'test subprocess RC=17')
    rawtrial('zero-matched-tests','evaluator.stdout',lambda b:b'','empty test output')
    def skip(data):
        es=[json.loads(s) for s in data.decode().splitlines()]
        hits=[e for e in es if e.get('Test')=='TestS2bCompetition/anchor/exact/1-priority' and e['Action']=='pass']
        if len(hits)!=1:raise RuntimeError('SKIP mutation identity not unique')
        hits[0]['Action']='skip';return ('\n'.join(json.dumps(e) for e in es)+'\n').encode()
    rawtrial('skipped-test','evaluator.stdout',skip,'test FAIL/SKIP identity')
    rawtrial('zero-c-execution','c-after/run/stdout.jsonl',lambda b:b'','C required execution identity/count/RC after')
    rawtrial('c-wrong-tree','c-after/replay-manifest.json',jsonmut(lambda o:o.update(root='/tmp/other-tree')),'C replay source manifest after/root')
    c=gate.load_c(instrument)
    for side,source_root in [('before',root/'node/agent/testdata/s2b-pre'),('after',root)]:
        unit,defs,_,_=c.extract(source_root,work/('wrong-shim-extract-'+side))
        generation,_=c.select_shim(defs)
        wrong=c.ATTRS_SHIM if generation=='packed' else c.PACKED_SHIM
        rawtrial('wrong-generation-shim-'+side,'c-'+side+'/replay.c',lambda b,u=unit,w=wrong:u+w.encode(),'C replay build identity/RC '+side)
    if path.read_bytes()!=pristine:raise RuntimeError('report restoration drift')


def raw_c_probes(root,work,instrument):
    c=gate.load_c(instrument);records=[]
    for side,contract,source in [('before','s2a',root/'node/agent/testdata/s2b-pre'),('after','s2b',root)]:
        binary,_=c.build_replay(source,work/side)
        inputs=[];expected=[]
        for stage in cases.STAGES:
            for label,bm,opts in [('retired-19',1<<19,{}),('retired-20',1<<20,{}),('retired-32',1<<32,{}),('high-63',1<<63,{}),
                                  ('all-ones',(1<<64)-1,{}),('fallback',0,{'fallback':1}),('zero',0,{}),('no-config',(1<<64)-1,{'cfg':0})]:
                row=cases.make_case(8,8,stage,'single-a');row['pair_id']='raw-'+label;row['bitmaps'][cases.group(stage)]=bm
                inputs.append(cases.c_input(row,**opts));expected.append((row,opts))
        actual=c.run_replay(binary,inputs,work/side/'run')
        for (row,opts),one in zip(expected,actual):
            cases.check_c(row,contract,one,**opts);records.append({'side':side,'test':cases.identity(row),'actual':one,'options':opts})
    (work/'raw-probes.json').write_text(json.dumps(records,indent=2)+'\n');print('raw C probes='+str(len(records)))


def facts_mutations(root,work,instrument):
    target=work/'source';shutil.copytree(root/'node',target/'node',ignore=shutil.ignore_patterns('__pycache__'),dirs_exist_ok=True)
    text_=(instrument/'internal_docs/_verify_facts.sh').read_text()
    a=text_.index('s1_dependency_count() {');b=text_.index('\n}\n',a)+2;function=text_[a:b]
    probe=target/'node/agent/s2b_dependency_linux.go';clean=b'package main\n';probe.write_bytes(clean)
    for arch in ('amd64','arm64'):
        for cgo in ('0','1'):
            def run():return subprocess.run(['bash','-c',function+'\ns1_dependency_count '+arch+' '+cgo],cwd=target,capture_output=True,text=True)
            def restore():probe.write_bytes(clean);return {str(probe):digest(probe)}
            record_trial(work,'DependencyIsolation/'+arch+'-cgo'+cgo+'/import-eval',run,
                lambda:probe.write_text('package main\nimport _ "github.com/littlewolf9527/xdrop/node/agent/eval"\n'),restore,'1/1')
            record_trial(work,'DependencyIsolation/'+arch+'-cgo'+cgo+'/failed-go-list',run,
                lambda:probe.write_text('package main\nimport _ "github.com/littlewolf9527/xdrop/node/agent/deliberately_missing_s2b_dependency"\n'),restore,'DEPENDENCY_COMMAND_FAILED','dependency command rejection')
    def fact_run(mode):return subprocess.run([sys.executable,str(instrument/'node/agent/tools/check_s2b_facts.py'),
        '--root',str(target),'--instrument-root',str(instrument),'--mode',mode],cwd=instrument,capture_output=True,text=True)
    old=target/'node/agent/eval/wire_test.go';original=old.read_bytes()
    def restore_test():old.write_bytes(original);return {str(old):digest(old)}
    record_trial(work,'FactsInventory/missing-historical-test',lambda:fact_run('inventory-identity'),
        lambda:old.rename(old.with_suffix('.absent')),restore_test,'current test file identity set differs')
    calibration=target/'node/agent/eval/calibrate_lab_test.go';original_cal=calibration.read_bytes()
    a=text_.index('ck() {');b=text_.index('\n}\n',a)+2;ck=text_[a:b]
    cmd=' '.join(__import__('shlex').quote(str(x)) for x in [sys.executable,instrument/'node/agent/tools/check_s2b_facts.py','--root',target,'--instrument-root',instrument,'--mode','prune-regular'])
    shell='PASS=0; FAIL=0; FACT_DIAG='+__import__('shlex').quote(str(work/'prune-diagnostics.log'))+'\n'+ck+'\nck F-008 regular 0 '+__import__('shlex').quote(cmd)+'\ntest "$FAIL" -eq 0\n'
    def restore_cal():calibration.write_bytes(original_cal);return {str(calibration):digest(calibration)}
    record_trial(work,'FactsPrune/removed-integration-tag',lambda:subprocess.run(['bash','-c',shell],cwd=target,capture_output=True,text=True),
        lambda:calibration.write_bytes(re.sub(rb'^//go:build[^\n]*\n',b'',original_cal,count=1,flags=re.M)),restore_cal,'期望 0，实测 1','static compilation-scope guard')
    # The candidate completion gate must reject the untouched post-S2a source.
    oldpaths=['node/bpf/xdrop_main.c','node/bpf/combo_masks.h']
    saved={p:(target/p).read_bytes() for p in oldpaths}
    def mutate_old():
        for p in oldpaths:(target/p).write_bytes((root/'node/agent/testdata/s2b-pre'/p).read_bytes())
    def restore_old():
        for p,data in saved.items():(target/p).write_bytes(data)
        return {p:digest(target/p) for p in oldpaths}
    record_trial(work,'FactsB0/unimplemented-old-tree',lambda:fact_run('b0'),mutate_old,restore_old,'s2b source identity','candidate identity rejection')


def c_order_mutations(root,work,instrument):
    for contract,base in [('s2b',root),('s2a',root/'node/agent/testdata/s2b-pre')]:
        target=work/contract/'source'
        pristine={p:(base/p).read_bytes() for p in ('node/bpf/xdrop_main.c','node/bpf/xdrop.h','node/bpf/combo_masks.h','node/bpf/xdrop_gate.c','node/bpf/headers/bpf_helpers.h')}
        for p,data in pristine.items():q=target/p;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(data)
        for fn,stage in [('lookup_rule','exact'),('lookup_rule_anomaly','anomaly_exact'),('lookup_cidr_rule','cidr'),('lookup_cidr_rule_anomaly','anomaly_cidr')]:
            definitions=[]
            if contract=='s2b':
                header=pristine['node/bpf/combo_masks.h'].decode();order=cases.check_order_header(header)
                for label,seq,a,b in [('numbered-table',list(cases.ACTIVE),5,24),('tie-table',[order[0],order[2],order[1]]+order[3:],1,22)]:
                    changed=re.sub(r'(static const __u8 combo_order\[\] = \{)[^{}]*(\};)',lambda m:m[1]+'\n    '+', '.join(map(str,seq))+',\n'+m[2],header)
                    definitions.append((label,'node/bpf/combo_masks.h',changed,cases.make_case(a,b,stage,'dual')))
            else:
                row=cases.make_case(5,24,stage,'dual');row['pair_id']='raw-retired-20';row['rules'][cases.group(stage)]=[];row['bitmaps'][cases.group(stage)]=1<<20
                changed=function_mutation(pristine['node/bpf/xdrop_main.c'].decode(),fn,replace_once('bitmap &= COMBO_VALID_BITMAP;',';'))
                definitions.append(('historical-dirty-bitmap-filter','node/bpf/xdrop_main.c',changed,row))
            for label,rel,changed,row in definitions:
                name='COrder/'+fn+'/'+label;directory=work/name;directory.mkdir(parents=True,exist_ok=True)
                inp=directory/'input.json';inp.write_text(json.dumps({'row':row,'options':{},'contract':contract})+'\n')
                def run():return subprocess.run([sys.executable,str(instrument/'node/agent/tools/mutation_check_s2b.py'),'--worker','--mode','runtime','--root',str(target),'--instrument',str(instrument),'--output',str(directory/'replay'),'--input',str(inp),'--test-id',name],cwd=instrument,capture_output=True,text=True)
                def mutate():
                    (target/rel).write_text(changed)
                    try:cases.source_identity(target,contract)
                    except cases.CaseError as e:
                        if 'source identity' not in str(e):raise RuntimeError('E6 identity rejection unrelated: '+str(e))
                        (directory/'identity-rejection.json').write_text(json.dumps({'rc':1,'error':str(e)})+'\n')
                    else:raise RuntimeError('source identity accepted mutant')
                def restore():
                    for p,data in pristine.items():(target/p).write_bytes(data)
                    return {p:digest(target/p) for p in pristine}
                record_trial(work,name,run,mutate,restore,'C probe/key trajectory','actual C behavior')


def s4_mutations(root, work, instrument):
    c = gate.load_c(instrument)
    target = work/'source'
    pristine = {p:(root/p).read_bytes() for p in ('node/bpf/xdrop_main.c','node/bpf/xdrop.h','node/bpf/combo_masks.h','node/bpf/headers/bpf_helpers.h')}
    for rel, data in pristine.items():
        p=target/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    source = pristine['node/bpf/xdrop_main.c'].decode()
    def packed(text):
        text=text.replace('const struct pkt_attrs *attrs','__u32 len_flags')
        text=text.replace('__u16 pkt_len = attrs->pkt_len;', '__u16 pkt_len = (__u16)(len_flags >> 8);')
        text=text.replace('__u8 tcp_flags = attrs->tcp_flags;', '__u8 tcp_flags = (__u8)(len_flags & 0xFF);')
        if 'pkt_anomaly = attrs->pkt_anomaly;' in text:
            text=text.replace('int rule_sel,','__u32 anom_sel,',1)
            text=text.replace('__u8 pkt_anomaly = attrs->pkt_anomaly;', '__u8 pkt_anomaly = (__u8)(anom_sel >> 1);\n  int rule_sel = (int)(anom_sel & 1);')
        return text
    swapped, count = re.subn(r'int rule_sel,\s*__u64 slot','__u64 slot, int rule_sel',source)
    if count != 4:raise RuntimeError('S4 swap anchor count')
    definitions = [
        ('last-two-swapped',swapped,'C interface signature: lookup_rule','static',None),
        ('parameter-name',re.sub(r'\brule_sel\b','selector',source),'C interface signature: lookup_rule','static',None),
        ('missing-const',source.replace('const struct pkt_attrs *attrs','struct pkt_attrs *attrs',1),'C interface signature: lookup_rule','static',None),
        ('unknown-signature',source.replace('int rule_sel,','__u32 rule_sel,',1),'C interface signature: lookup_rule','static',None),
        ('mixed-generation',function_mutation(source,'lookup_rule',packed),'C interface mixed generations','static',None),
    ]
    all_packed=source
    for fn in c.NAMES[4:]:all_packed=function_mutation(all_packed,fn,packed)
    definitions.append(('current-packed',all_packed,'C current interface must be attrs','static',None))
    for fn in c.NAMES[4:]:
        old='__u16 pkt_len = attrs->pkt_len;'
        for label,new in [('truncate','__u16 pkt_len = (__u8)attrs->pkt_len;'),('temporary','__u8 tmp = attrs->pkt_len;\n  __u16 pkt_len = tmp;')]:
            definitions.append((fn+'/'+label,function_mutation(source,fn,replace_once(old,new)),'C complete pre-loop prefix: '+fn,'static',None))
    definitions += [
        ('field-width',replace_once('__u16 pkt_len;','__u8 pkt_len;')(source),'C attrs width compilation','widths',None),
        ('old-symbol',source+'\n// len_flags cleanup control\n','C old packing symbols','symbols',None),
        ('helper-freeze',function_mutation(source,'pkt_len_matches',lambda s:s.replace('{','{\n  /* hash control */',1)),'C helper source contract: pkt_len_matches','static',None),
    ]
    for name,old in [
        ('exact','&attrs, rule_sel, config_slot);'),('cidr','&cidr_attrs, rule_sel, config_slot);'),
        ('anomaly_exact','&st->key, &matched_key, &attrs, rule_sel & 1, config_slot);'),
        ('anomaly_cidr','&ck, &cidr_matched_key, &cidr_attrs, rule_sel & 1, config_slot);'),
    ]:definitions.append(('caller/'+name,replace_once(old,old.replace('config_slot','0'))(source),'S4 caller text','callers',None))
    for row in cases.width_cases():
        fn='lookup_cidr_rule' if row['stage']=='cidr' else 'lookup_rule'
        definitions.append(('width-runtime/'+row['stage'],function_mutation(source,fn,replace_once('__u16 pkt_len = attrs->pkt_len;','__u16 pkt_len = (__u8)attrs->pkt_len;')),'C winner','runtime',row))
    if len(definitions)!=23:raise RuntimeError('S4 registered mutation identity count')
    path=target/'node/bpf/xdrop_main.c'
    def restore():
        for rel,data in pristine.items():(target/rel).write_bytes(data)
        return {rel:digest(target/rel) for rel in pristine}
    for label,mutant,red,mode,row in definitions:
        name='S4/'+label;directory=work/name;directory.mkdir(parents=True,exist_ok=True)
        inp=directory/'input.json';inp.write_text(json.dumps({'row':row,'options':{}})+'\n')
        def run():
            cmd=[sys.executable,str(instrument/'node/agent/tools/mutation_check_s2b.py'),'--worker','--mode',mode,'--root',str(target),'--instrument',str(instrument),'--output',str(directory/'result'),'--test-id',name]
            if mode=='runtime':cmd+=['--input',str(inp)]
            return subprocess.run(cmd,cwd=instrument,capture_output=True,text=True)
        record_trial(work,name,run,lambda text=mutant:path.write_text(text),restore,red,'S4 boundary')
    for rel,data in pristine.items():
        if hashlib.md5((root/rel).read_bytes()).digest()!=hashlib.md5(data).digest():raise RuntimeError('S4 original MD5 drift')
    if not PREFLIGHT_ONLY:print('S4 mutants=23/23 original_preserved=1')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',required=True,type=Path);ap.add_argument('--instrument',required=True,type=Path);ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--suite',choices=['c','tables','report','raw','facts','c-order','s4'],default='c');ap.add_argument('--report-dir',type=Path)
    ap.add_argument('--preflight-only',action='store_true')
    ap.add_argument('--selfcheck-report',type=Path)
    ap.add_argument('--worker',action='store_true');ap.add_argument('--mode',choices=['runtime','static','widths','symbols','callers']);ap.add_argument('--input',type=Path);ap.add_argument('--test-id')
    args=ap.parse_args()
    global PREFLIGHT_ONLY
    PREFLIGHT_ONLY=args.preflight_only
    if any(not p.is_absolute() for p in (args.root,args.instrument,args.output)):ap.error('absolute paths required')
    if args.worker:worker(args)
    else:
        if not PREFLIGHT_ONLY and args.suite!='raw':
            from check_s2b_apparatus import fingerprint
            if args.selfcheck_report is None:ap.error('all-group selfcheck certificate required before mutations')
            proof=json.loads(args.selfcheck_report.read_text())
            if (proof.get('schema')!='s2b-apparatus-selfcheck-v1' or proof.get('passed') is not True or
                proof.get('fingerprint')!=fingerprint(args.instrument) or
                len(proof.get('rows',[]))!=171 or any(not row['passed'] for row in proof['rows']) or
                args.output.resolve()!=Path(proof['suite_outputs'][args.suite]).resolve()):
                ap.error('selfcheck missing, failed, stale, or different mutation environment')
        args.output.mkdir(parents=True,exist_ok=True)
        if args.suite=='c':
            rows=c_mutations(args.root,args.output,args.instrument);print(f'C targeted mutants={len(rows)} original_preserved=1')
        elif args.suite=='tables':table_mutations(args.root,args.output,args.instrument)
        elif args.suite=='report':report_mutations(args.root,args.output,args.instrument,args.report_dir)
        elif args.suite=='raw':raw_c_probes(args.root,args.output,args.instrument)
        elif args.suite=='facts':facts_mutations(args.root,args.output,args.instrument)
        elif args.suite=='s4':s4_mutations(args.root,args.output,args.instrument)
        else:c_order_mutations(args.root,args.output,args.instrument)


if __name__=='__main__':
    try:main()
    except Exception as e:
        print(str(e),file=sys.stderr);sys.exit(1)
