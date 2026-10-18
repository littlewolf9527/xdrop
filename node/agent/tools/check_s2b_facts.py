#!/usr/bin/env python3
"""B0 facts wiring: fixed history, explicit live tree and actual behavior."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

import check_s2b as gate
import s2b_cases as cases

FREEZE_MANIFEST='e09a07ab6feac497c8d3add8d7bf78ddd0521f5f53310bccde439959a0870d21'
PREFIX='node/agent/testdata/s2b-pre/'
NEW_TESTS={PREFIX+'node/agent/eval/'+n for n in ('calibrate_lab_test.go','eval_test.go','fixtures_test.go','s2a_test.go','wire_test.go')}|{'node/agent/eval/s2b_test.go','node/agent/api/s4_pkt_attrs_source_test.go','node/agent/bpf/main_pkt_attrs_source_test.go','node/agent/bpf/b1_extract_test.go','node/agent/bpf/b1_conditions_test.go','node/agent/eval/b1_test.go'}
MODIFIED_TESTS={'node/agent/eval/eval_test.go','node/agent/eval/s2a_test.go'}


def frozen(root):
    base=root/PREFIX;manifest=base/'manifest.json'
    if gate.sha(manifest)!=FREEZE_MANIFEST:raise ValueError('frozen S2a manifest identity')
    data=json.loads(manifest.read_text())
    if data['source_commit']!=cases.SOURCE_COMMIT or len(data['files'])!=20:raise ValueError('frozen S2a source commit/file identities')
    actual={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}
    if actual!=set(data['files'])|{'README.md','manifest.json'}:raise ValueError('frozen S2a exact file identity set')
    for rel,digest in data['files'].items():
        if (base/rel).is_symlink() or gate.sha(base/rel)!=digest:raise ValueError('frozen S2a bytes '+rel)
    return len(data['files'])


def test_inventory(root,instrument):
    names=subprocess.check_output(['git','ls-tree','-r','--name-only',cases.SOURCE_COMMIT,'node'],cwd=instrument,text=True).splitlines()
    names={p for p in names if p.endswith('_test.go')}
    before={p:subprocess.check_output(['git','show',cases.SOURCE_COMMIT+':'+p],cwd=instrument) for p in names}
    after={str(p.relative_to(root)):p.read_bytes() for p in (root/'node').rglob('*_test.go')}
    if set(after)!=set(before)|NEW_TESTS:raise ValueError('current test file identity set differs from pinned history plus B0 additions')
    if {p for p in before if before[p]!=after[p]}!=MODIFIED_TESTS:raise ValueError('historical test byte changes outside explicit B0 migration')
    frozen(root)
    def counts(fs):return [len(fs),sum(b.count(b'\n') for b in fs.values()),sum(bool(re.search(rb'^//go:build',b,re.M)) for b in fs.values())]
    old,new=counts(before),counts(after)
    if old!=[35,8761,11]:raise ValueError('pinned historical inventory differs')
    detail={'root':str(root),'commit':cases.SOURCE_COMMIT+'+working-tree','history_commit':cases.SOURCE_COMMIT,
            'before':old,'after':new,'delta':[{'path':p,'before_lines':before.get(p,b'').count(b'\n'),'after_lines':after[p].count(b'\n'),'sha256':hashlib.sha256(after[p]).hexdigest()} for p in sorted(NEW_TESTS|MODIFIED_TESTS)]}
    print(json.dumps(detail,sort_keys=True),file=sys.stderr)
    return old,new


def prune_counts(root):
    # Count the active compilation scope separately; authenticate every excluded
    # frozen hit by its fixed manifest, so dropping its tag cannot disappear.
    frozen(root)
    hits={str(p.relative_to(root)):p.read_text() for p in (root/'node').rglob('*_test.go') if re.search(r'T51|verifier_prune_map|prune_hit',p.read_text())}
    historical=PREFIX+'node/agent/eval/calibrate_lab_test.go'
    if historical not in hits:raise ValueError('prune frozen positive identity absent')
    frozen_hits=[p for p in hits if p.startswith(PREFIX)]
    if frozen_hits!=[historical]:raise ValueError('prune frozen positive identity not unique')
    active={p:s for p,s in hits.items() if p!=historical}
    regular=[p for p,s in active.items() if not re.search(r'^//go:build.*integration',s,re.M)]
    integration=[p for p,s in active.items() if re.search(r'^//go:build.*integration',s,re.M)]
    if set(active)!={'node/agent/eval/calibrate_lab_test.go'}:raise ValueError('prune active positive identity set')
    print(json.dumps({'active_regular':regular,'active_integration':integration,'frozen':frozen_hits}),file=sys.stderr)
    return len(regular),len(integration),len(frozen_hits)


def b0(root,instrument):
    output=Path(tempfile.mkdtemp(prefix='s2b-facts-',dir='/tmp'))
    before=root/PREFIX
    cmd=[sys.executable,str(instrument/'node/agent/tools/check_s2b.py'),'--before-root',str(before),'--before-contract','s2a','--after-root',str(root),'--after-contract','s2b','--instrument-root',str(instrument),'--output',str(output)]
    p=subprocess.run(cmd,cwd=instrument,capture_output=True,text=True)
    (output/'gate.stdout').write_text(p.stdout);(output/'gate.stderr').write_text(p.stderr);(output/'gate.rc').write_text(str(p.returncode)+'\n')
    print(json.dumps({'root':str(root),'commit':cases.SOURCE_COMMIT+'+working-tree','output':str(output),'rc':p.returncode}),file=sys.stderr)
    if p.returncode:raise ValueError('B0 actual gate failed: '+p.stdout+p.stderr)
    summary=json.loads(p.stdout.splitlines()[-1]);report=json.loads((output/'report.json').read_text())
    order=cases.check_order_header((root/'node/bpf/combo_masks.h').read_text())
    pairs={r['pair_id']:r['pair_relation'] for r in report['rows'] if re.fullmatch(r'\d{2}-\d{2}',r['pair_id'])}
    relations=Counter(pairs.values())
    if relations!={'reversed-containment':124,'reversed-incomparable':125,'unchanged-weight':106,'unchanged-tie':110}:raise ValueError('pair relation identity counts')
    # All-miss raw bitmap probes reveal every actual consumer position, including
    # the tail. They are outside RuleSet validation and never normal input rows.
    c=gate.load_c(instrument);rows=[]
    for stage in cases.STAGES:
        row=cases.make_case(5,24,stage,'dual');row['rules'][cases.group(stage)]=[];row['bitmaps'][cases.group(stage)]=(1<<64)-1;rows.append(row)
    actual=c.run_replay(output/'c-after/replay',[cases.c_input(r) for r in rows],output/'full-order-probes')
    inversions=0;measured=[]
    for row,result in zip(rows,actual):
        cases.check_c(row,'s2b',result)
        keys={cases.wire(cases.key_for(n,row['packet'],'cidr' in row['stage']),'cidr' in row['stage']):n for n in cases.ACTIVE}
        if len(keys)!=31:raise ValueError('order probe key identities not unique')
        seq=[keys[p['key']] for p in result['probes']]
        if seq!=order:raise ValueError('actual C full probe order differs')
        n=sum(bin(cases.mask(a)).count('1')<bin(cases.mask(b)).count('1') for i,a in enumerate(seq) for b in seq[i+1:]);inversions+=n
        measured.append({'stage':row['stage'],'actual_order':seq,'field_inversions':n})
    (output/'full-order-probes/summary.json').write_text(json.dumps(measured,indent=2)+'\n')
    return '/'.join(map(str,[len(order),len(pairs),summary['report_rows'],summary['c_rows_each'],len(actual),inversions]))


# Kernel-anchored verifier budget; m0probe prints this same ceiling.
VERIFIER_BUDGET = 1000000
# No single entry may consume more than half the budget. The historical split
# (F-058) was made at 91.55%; 50% is a line well before that catastrophe.
ENTRY_CEILING = VERIFIER_BUDGET // 2
# Per-knife absolute delta cap, in instructions (= 2.0 percentage points of the
# budget). ENGINEERING QUOTA, not a derived safe value: the original arithmetic
# split the 33.7pp headroom across "B1-B8, eight knives", but only B1/B2/B3
# touch the data plane (B4/B5 are database work, B6-B8 control/node plane), so
# the equal-share assumption does not hold. What is actually accepted here are
# the MEASURED deltas +2186/+4036/0, frozen below and re-measured on drift.
# Absolute by construction: unlike a relative percentage it does not penalise a
# small program for having a small baseline.
ENTRY_INSTRUCTION_DELTA = VERIFIER_BUDGET * 2 // 100
# Per-knife stack delta cap: one eighth of the 512-byte chain limit.
ENTRY_STACK_DELTA = 64

# F-117 measured baseline. Synthetic selftests below verify only this parser.
F117_RESOURCES = {
    'xdp_firewall_main': (160815, [320, 32, 32, 0, 0]),
    'xdp_anomaly_verify': (23303, [136, 40, 40, 0, 0]),
    'xdp_whitelist_gate': (36149, [336]),
}


def parse_m0_resources(text):
    entries = list(re.finditer(r'^──── 入口 (\w+) ────$', text, re.M))
    if sorted(m[1] for m in entries) != sorted(F117_RESOURCES):
        raise ValueError('S4 resource entry identities')
    if len(re.findall(r'^本轮结果【[^\n]+】: ✅ 全部程序通过 verifier$', text, re.M)) != 1 or '🔴' in text:
        raise ValueError('S4 resource successful load summary')
    result = {}
    for i, match in enumerate(entries):
        block = text[match.end():entries[i + 1].start() if i + 1 < len(entries) else len(text)]
        instructions = re.findall(r'^✅ VerifiedInstructions = ([0-9]+)\s+\(', block, re.M)
        stacks = re.findall(r'^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$', block, re.M)
        if len(instructions) != 1 or int(instructions[0]) <= 0:
            raise ValueError('S4 resource instructions missing/duplicate: ' + match[1])
        if len(stacks) != 1:
            raise ValueError('S4 resource stack missing/duplicate: ' + match[1])
        result[match[1]] = (int(instructions[0]), list(map(int, stacks[0].split('+'))))
    return result


def check_resources(before_text, after_text, context):
    if type(context) is not dict or set(context) != {'before', 'after'}:
        raise ValueError('S4 resource environment context')
    fields = {'kernel', 'clang', 'arch', 'probe_sha256', 'rc'}
    for side in ('before', 'after'):
        obj = context[side]
        if (type(obj) is not dict or set(obj) != fields or type(obj['rc']) is not int or obj['rc'] != 0 or
                any(type(obj[k]) is not str or not obj[k].strip() for k in fields - {'rc'}) or
                not re.fullmatch('[0-9a-f]{64}', obj['probe_sha256'])):
            raise ValueError('S4 resource environment/RC: ' + side)
    if context['before'] != context['after']:
        raise ValueError('S4 resource incomparable environment')
    if context['before']['kernel'] != '6.12.57+deb13-amd64' or context['before']['clang'] != '19.1.7':
        raise ValueError('S4 resource F-117 toolchain/environment')
    before, after = parse_m0_resources(before_text), parse_m0_resources(after_text)
    if before != F117_RESOURCES:
        raise ValueError('S4 resource F-117 baseline readings')
    readings = []
    for name, (instructions, frames) in after.items():
        old_instructions, old_frames = before[name]
        if sum(frames) > 512:
            raise ValueError('S4 resource conservative stack sum: ' + name)
        if name == 'xdp_firewall_main' and frames[0] - old_frames[0] > 32:
            raise ValueError('S4 resource main frame delta')
        # Absolute budget gate (2026-09-20). The previous rule was relative
        # (after <= before * 1.10) and reported red on xdp_anomaly_verify at
        # +17.32% while that entry spends only 2.73% of the budget and the same
        # change costs 0.40pp absolute. A relative cap penalises whichever entry
        # has the smallest baseline -- but note this change DID raise the
        # instruction ceiling for all three entries (176896/25633/39763 ->
        # 180815/43303/56149). The accurate statement is that the owner accepted
        # this cost and authorised a looser instruction policy on 2026-09-20; the
        # evidence does not show the cost was unavoidable. The +17.32% reading is
        # retained in facts.md F-118 and in every record emitted below.
        if instructions > ENTRY_CEILING:
            raise ValueError('S4 resource budget ceiling: ' + name)
        if instructions - old_instructions > ENTRY_INSTRUCTION_DELTA:
            raise ValueError('S4 resource instruction delta: ' + name)
        if sum(frames) - sum(old_frames) > ENTRY_STACK_DELTA:
            raise ValueError('S4 resource stack delta: ' + name)
        readings.append({'entry': name, 'before_instructions': old_instructions,
                         'after_instructions': instructions, 'growth_percent': 100 * (instructions / old_instructions - 1),
                         'budget_percent': 100 * instructions / VERIFIER_BUDGET,
                         'instruction_delta': instructions - old_instructions,
                         'delta_budget_points': 100 * (instructions - old_instructions) / VERIFIER_BUDGET,
                         'frames': frames, 'conservative_sum': sum(frames),
                         'stack_delta': sum(frames) - sum(old_frames),
                         'main_frame_delta': frames[0] - old_frames[0] if name == 'xdp_firewall_main' else None})
    return readings


# Frozen gate-7 acceptance record (2026-09-20 lab run). These pin WHICH logs
# were accepted, WHAT they said, and WHICH source they were taken from. The
# plain re-run gate could not tell before.log from after.log, could not see a
# one-digit drift, and did not bind to any tree: external review reproduced all
# three. Pinning them here is what makes this a real-machine acceptance record
# instead of a judge regression test.
GATE7_ARCHIVE = 'internal_docs/audits/2026-09-20-s4-gate7'
GATE7_EVIDENCE = {
    'before.log': 'e504ac64eb6b6ccd799c7cc912bb9bcc2f55459ae1feda80b6d31e25662f207e',
    'after.log': '5e36781d699ef2b27ed56505c0955c2db2d7881536843e1026fe9f292acc3597',
    'resource-context.json': 'f6275f59aaa53aea916c3cfcdab3cb863ae6a1bf1e1c37e8b4f1705bd7bbbdb9',
}
GATE7_ACCEPTED = {
    'xdp_firewall_main': (163001, [328, 40, 40, 0, 0]),
    'xdp_anomaly_verify': (27339, [152, 48, 48, 0, 0]),
    'xdp_whitelist_gate': (36149, [336]),
}
# Every file the two ELFs are compiled from, enumerated by `clang -MM` on both
# .c files plus the Makefile that carries the flags. If any of them moves, the
# archived readings are stale and gate 7 must be re-run on lab.
# SCOPE, stated exactly (external review 2026-09-20): this checks only that the
# LIVE files still have the registered content. It does NOT prove the registered
# values came from the scratch trees that produced the probed ELFs, and it does
# NOT bind the ELF bytes the probe actually loaded -- the archive has no ELF SHA
# and m0probe does not print one. That link rests on the operator record in
# audits/2026-09-20-s4-gate7/. A machine-auditable chain requires a NEW
# measurement recording source -> command -> ELF SHA -> loaded identity;
# it must not be back-filled onto this one.
GATE7_INPUTS = {
    'node/bpf/xdrop_main.c': '2a111fa26dc87b5bcd90fd26405edc290ee281375208041775d48650d34b2c32',
    'node/bpf/xdrop_gate.c': 'a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199',
    'node/bpf/xdrop.h': 'd1dd8269ab0dfb0923e565fe075f830f652e150b0e741f9869d1231d967833d2',
    'node/bpf/combo_masks.h': 'b296d4d1798f7fdff7d0b42484e38bbab930e57ed499510a63f1fe5dc3470172',
    'node/bpf/headers/bpf_helpers.h': 'ac22dae8c99e5702073d8ecd9fc75beb9fc29c67a2a1face4211cca579ba2d13',
    'node/bpf/Makefile': 'be83e5a238950554e9d5638e05119783d9b4089964cbfa334e412abeb0eaf837',
}


def resources_accepted(root):
    """Frozen acceptance: pinned evidence, pinned readings, pinned source."""
    archive = root/GATE7_ARCHIVE
    # Read each file EXACTLY ONCE, verify the SHA of those bytes, then parse the
    # same bytes. Hashing and re-reading let a file swapped between the two
    # reads be judged unverified (external review reproduced it 2026-09-20).
    blob = {}
    for name, want in sorted(GATE7_EVIDENCE.items()):
        path = archive/name
        if not path.is_file():
            raise ValueError('S4 gate7 archive missing: ' + name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != want:
            raise ValueError('S4 gate7 archive identity: ' + name)
        blob[name] = data
    evidence = len(blob)
    readings = check_resources(blob['before.log'].decode(),
                               blob['after.log'].decode(),
                               json.loads(blob['resource-context.json'].decode()))
    accepted = 0
    for row in readings:
        want = GATE7_ACCEPTED.get(row['entry'])
        if want is None or row['after_instructions'] != want[0] or row['frames'] != want[1]:
            raise ValueError('S4 gate7 accepted reading: ' + row['entry'])
        accepted += 1
    if accepted != len(GATE7_ACCEPTED):
        raise ValueError('S4 gate7 accepted entry count')
    inputs = 0
    for rel, want in sorted(GATE7_INPUTS.items()):
        path = root/rel
        if not path.is_file():
            raise ValueError('S4 gate7 compile input missing: ' + rel)
        if hashlib.sha256(path.read_bytes()).hexdigest() != want:
            raise ValueError('S4 gate7 input drifted, re-run gate 7 on lab: ' + rel)
        inputs += 1
    return f'{evidence}/{accepted}/{inputs}'


def resource_selftest(output):
    """Retain explicitly synthetic records; never mark them as kernel evidence."""
    import copy
    output.mkdir(parents=True, exist_ok=True)
    def log(readings):
        return '\n'.join('──── 入口 ' + name + ' ────\n✅ VerifiedInstructions = ' + str(vi) +
                         '   (synthetic fixture)\nstack depth ' + '+'.join(map(str, frames))
                         for name, (vi, frames) in readings.items()) + '\n本轮结果【SYNTHETIC】: ✅ 全部程序通过 verifier\n'
    original = log(F117_RESOURCES)
    context = {'before': {'kernel': '6.12.57+deb13-amd64', 'clang': '19.1.7', 'arch': 'x86_64', 'probe_sha256': '0' * 64, 'rc': 0}}
    context['after'] = dict(context['before'])
    assert len(check_resources(original, original, context)) == 3
    (output/'SYNTHETIC-before.log').write_text(original)
    (output/'SYNTHETIC-context.json').write_text(json.dumps(context, indent=2)+'\n')
    trials = []
    for name, (vi, frames) in F117_RESOURCES.items():
        changed = copy.deepcopy(F117_RESOURCES); changed[name] = (ENTRY_CEILING + 1, frames)
        trials.append((name+'/ceiling', log(changed), context, 'S4 resource budget ceiling'))
        changed = copy.deepcopy(F117_RESOURCES); changed[name] = (vi + ENTRY_INSTRUCTION_DELTA + 1, frames)
        trials.append((name+'/instruction-delta', log(changed), context, 'S4 resource instruction delta'))
        # Bump the LAST frame so xdp_firewall_main's first-frame rule cannot
        # steal this red point; the sum stays under the 512 chain limit so the
        # conservative-sum rule cannot steal it either.
        bumped = list(frames); bumped[-1] += ENTRY_STACK_DELTA + 1
        changed = copy.deepcopy(F117_RESOURCES); changed[name] = (vi, bumped)
        trials.append((name+'/stack-delta', log(changed), context, 'S4 resource stack delta'))
        changed = copy.deepcopy(F117_RESOURCES); changed[name] = (vi, [513])
        trials.append((name+'/stack', log(changed), context, 'S4 resource conservative stack sum'))
        changed = copy.deepcopy(F117_RESOURCES); del changed[name]
        trials.append((name+'/missing-entry', log(changed), context, 'S4 resource entry identities'))
        trials.append((name+'/missing-instructions', original.replace('✅ VerifiedInstructions = '+str(vi), 'absent', 1), context, 'S4 resource instructions missing/duplicate'))
        trials.append((name+'/missing-stack', original.replace('stack depth '+'+'.join(map(str, frames)), 'absent', 1), context, 'S4 resource stack missing/duplicate'))
    changed = copy.deepcopy(F117_RESOURCES); changed['xdp_firewall_main'] = (160815, [353, 32, 32, 0, 0])
    trials.append(('main-frame-delta', log(changed), context, 'S4 resource main frame delta'))
    changed_context = copy.deepcopy(context); changed_context['after']['rc'] = 1
    trials.append(('failed-command', original, changed_context, 'S4 resource environment/RC'))
    changed_context = copy.deepcopy(context); changed_context['after']['clang'] = 'different'
    trials.append(('different-toolchain', original, changed_context, 'S4 resource incomparable environment'))
    path = output/'SYNTHETIC-after.log'; path.write_text(original)
    original_md5 = hashlib.md5(path.read_bytes()).hexdigest()
    records = []
    for label, mutant, ctx, expected in trials:
        path.write_text(mutant)
        try:
            try: check_resources(original, path.read_text(), ctx)
            except ValueError as error:
                if expected not in str(error): raise
                records.append({'test': label, 'expected_red': expected, 'actual_red': str(error)})
            else: raise ValueError('S4 resource mutant accepted: ' + label)
        finally:
            path.write_text(original)
            if hashlib.md5(path.read_bytes()).hexdigest() != original_md5:
                raise ValueError('S4 resource restoration MD5')
            print('S4_RESOURCE_RESTORE '+label+' md5='+original_md5, file=sys.stderr)
    (output/'numeric-selftest.json').write_text(json.dumps({'synthetic': True, 'kernel_acceptance': False, 'positive_entries': 3, 'rejected': records, 'restored_md5': original_md5}, indent=2)+'\n')
    print('S4_RESOURCE_SYNTHETIC positives=3/3 rejected='+str(len(records))+'/'+str(len(trials))+' kernel_acceptance=UNTESTED artifacts='+str(output), file=sys.stderr)
    return '3/'+str(len(records))


def s4_callers(root, instrument):
    env = dict(__import__('os').environ, S4_SOURCE_ROOT=str(root))
    p = subprocess.run(['go', 'test', '-json', '-count=1', './api/', '-run', '^TestS4PacketAttrsSourceLock$'],
                       cwd=instrument/'node/agent', env=env, capture_output=True, text=True)
    expected = {'TestS4PacketAttrsSourceLock'} | {'TestS4PacketAttrsSourceLock/'+s for s in cases.STAGES}
    try: gate.executed(p.stdout, p.returncode, gate.PKG+'api', expected)
    except ValueError as error: raise ValueError('S4 caller text: '+str(error)+'\n'+p.stdout+p.stderr)
    return 4



# B1 is a separate contract. F-117/F-118 above remain immutable history.
B1_ENTRIES = {'xdp_firewall_main', 'xdp_anomaly_verify', 'xdp_whitelist_gate'}
B1_BASE_COMMIT = 'd0bf3a781414e74613814d352552bf4e68273f65'
B1_INPUTS = set(GATE7_INPUTS) | {
    'node/bpf/tools/extract_combo_masks.py', 'node/bpf/tools/s2b_c_replay.py',
    'node/bpf/tools/combo_masks_pre_m1.json',
}
B1_ELFS = {'xdrop_main.elf', 'xdrop_gate.elf'}


def b1_json(raw):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError('B1 duplicate JSON key: ' + k)
            obj[k] = v
        return obj
    return json.loads(raw, object_pairs_hook=unique)


def b1_read_record(path, expected):
    """Authenticate bytes once, then parse those exact bytes. No live-tree fallback."""
    raw = path.read_bytes()
    record = b1_json(raw)
    fields = {'source_commit', 'context', 'inputs', 'artifacts'}
    if type(record) is not dict or set(record) != fields:
        raise ValueError('B1 record fields')
    context = record['context']
    if (type(context) is not dict or set(context) != {'kernel', 'clang', 'arch', 'probe_sha256', 'rc'} or
            type(context['rc']) is not int or context['rc'] != 0 or
            any(type(context[k]) is not str or not context[k].strip() for k in context if k != 'rc')):
        raise ValueError('B1 environment/RC')
    if type(record['source_commit']) is not str or not re.fullmatch('[0-9a-f]{40}', record['source_commit']):
        raise ValueError('B1 source commit')
    if set(record['inputs']) != B1_INPUTS:
        raise ValueError('B1 compile input set')
    artifacts = B1_ELFS | {'build.log', 'probe.log', 'm0probe'}
    if set(record['artifacts']) != artifacts:
        raise ValueError('B1 artifact set')
    blobs = {}
    for prefix, hashes in [('inputs/', record['inputs']), ('', record['artifacts'])]:
        for name, digest in hashes.items():
            file = path.parent / (prefix + name)
            if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}', digest):
                raise ValueError('B1 SHA256 format: ' + name)
            data = file.read_bytes()
            if not data or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('B1 evidence hash: ' + name)
            blobs[prefix + name] = data
    if context['probe_sha256'] != record['artifacts']['m0probe']:
        raise ValueError('B1 probe identity')
    # make's executed recipe output, not make -n or an operator-supplied label.
    commands = [shlex.split(line) for line in blobs['build.log'].decode().splitlines() if line.startswith('clang ')]
    if len(commands) != 2:
        raise ValueError('B1 expanded compile command set')
    for name in ('xdrop_main', 'xdrop_gate'):
        command = 'clang -O2 -g -Wall -target bpf -D__BPF__ -I./headers  -c ' + name + '.c -o ' + name + '.elf'
        if commands.count(shlex.split(command)) != 1:
            raise ValueError('B1 expanded compile command: ' + name)
    log = blobs['probe.log'].decode()
    if len(re.findall(r'^本轮结果【[^\n]+】: ✅ 全部程序通过 verifier$', log, re.M)) != 1 or '🔴' in log:
        raise ValueError('B1 successful load summary')
    elf_sections = list(re.finditer(r'^ELF: ([^\n]+)$', log, re.M))
    if len(re.findall(r'^──── 入口 (\w+) ────$', log, re.M)) != len(expected):
        raise ValueError('B1 entry identities')
    if len(elf_sections) != 2:
        raise ValueError('B1 loaded ELF set')
    seen, readings = set(), {}
    for i, section in enumerate(elf_sections):
        name = Path(section[1]).name
        if name not in B1_ELFS or name in seen:
            raise ValueError('B1 loaded ELF set')
        seen.add(name)
        block = log[section.end():elf_sections[i+1].start() if i+1 < len(elf_sections) else len(log)]
        hashes = re.findall(r'^ELF sha256: ([0-9a-f]{64})  \(([0-9]+) bytes, 哈希与加载用同一份字节\)$', block, re.M)
        if hashes != [(record['artifacts'][name], str(len(blobs[name])))]:
            raise ValueError('B1 loaded ELF identity: ' + name)
        entries = list(re.finditer(r'^──── 入口 (\w+) ────$', block, re.M))
        assigned = {'xdp_whitelist_gate'} if name == 'xdrop_gate.elf' else B1_ENTRIES - {'xdp_whitelist_gate'}
        if sorted(m[1] for m in entries) != sorted(expected & assigned):
            raise ValueError('B1 entry identities: ' + name)
        for j, entry in enumerate(entries):
            text = block[entry.end():entries[j+1].start() if j+1 < len(entries) else len(block)]
            vi = re.findall(r'^✅ VerifiedInstructions = ([0-9]+)\s+\(', text, re.M)
            frames = re.findall(r'^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$', text, re.M)
            if len(vi) != 1 or int(vi[0]) <= 0:
                raise ValueError('B1 instructions missing/duplicate: ' + entry[1])
            if len(frames) != 1:
                raise ValueError('B1 frames missing/duplicate: ' + entry[1])
            processed = re.findall(r'^processed ([0-9]+) insns \(limit 1000000\)', text, re.M)
            if processed != vi:
                raise ValueError('B1 raw verifier reading: ' + entry[1])
            if int(vi[0]) > ENTRY_CEILING:
                raise ValueError('B1 budget ceiling: ' + entry[1])
            readings[entry[1]] = {'instructions': int(vi[0]), 'frames': list(map(int, frames[0].split('+')))}
    return record, readings, hashlib.sha256(raw).hexdigest()


def b1_resources(before_path, after_path, before_sha256, expected, retired, knife, root):
    # The caller declares lifecycle intent. Missing readings never retire an entry.
    if (not 1 <= knife <= 5 or len(expected) != len(set(expected)) or len(retired) != len(set(retired)) or
            set(expected) & set(retired) or set(expected) | set(retired) != B1_ENTRIES or
            set(retired) != ({'xdp_anomaly_verify'} if knife == 5 else set())):
        raise ValueError('B1 explicit entry contract')
    before, old, digest = b1_read_record(before_path, B1_ENTRIES)
    if digest != before_sha256:
        raise ValueError('B1 registered before identity')
    if knife == 1:
        if before['source_commit'] != B1_BASE_COMMIT:
            raise ValueError('B1 first anchor commit')
        for name, sha256 in before['inputs'].items():
            data = subprocess.check_output(['git', 'show', B1_BASE_COMMIT + ':' + name], cwd=root)
            if hashlib.sha256(data).hexdigest() != sha256:
                raise ValueError('B1 first anchor source: ' + name)
    after, new, after_sha = b1_read_record(after_path, set(expected))
    if before['context'] != after['context']:
        raise ValueError('B1 incomparable environment/probe')
    # A self-consistent archive can still describe an older tree. Bind every
    # measured compile input to the explicitly supplied tree before accepting.
    for name, sha256 in sorted(after['inputs'].items()):
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != sha256:
            raise ValueError('B1 after source drift: ' + name)
    rows = [{'entry': name, 'verdict': 'PASS', 'before_instructions': old[name]['instructions'],
             'after_instructions': new[name]['instructions'],
             'budget_percent': 100 * new[name]['instructions'] / VERIFIER_BUDGET,
             'before_frames': old[name]['frames'], 'frames': new[name]['frames']}
            for name in sorted(expected)]
    return {'contract': 'B1', 'knife': knife, 'verdict': 'PASS', 'before_sha256': digest,
            'after_sha256': after_sha, 'expected_entries': sorted(expected),
            'retired_entries': sorted(retired), 'entries': rows}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',required=True,type=Path);ap.add_argument('--instrument-root',required=True,type=Path)
    ap.add_argument('--mode',required=True,choices=['frozen','historical-inventory','inventory-identity','prune-regular','prune-integration','prune-frozen','b0','s4-interface','s4-widths','s4-symbols','s4-callers','s4-resources-selftest','s4-resources','s4-resources-accepted','b1-resources'])
    ap.add_argument('--before-log', type=Path); ap.add_argument('--after-log', type=Path)
    ap.add_argument('--resource-context', type=Path)
    ap.add_argument('--before-record', type=Path); ap.add_argument('--after-record', type=Path)
    ap.add_argument('--before-sha256'); ap.add_argument('--knife', type=int)
    ap.add_argument('--expected-entries'); ap.add_argument('--retired-entries')
    a=ap.parse_args()
    if any(not p.is_absolute() for p in (a.root,a.instrument_root)):ap.error('absolute roots required')
    commit = B1_BASE_COMMIT if a.mode.startswith('b1-') else cases.SOURCE_COMMIT
    print(f'tree={a.root} commit={commit}+working-tree instrument={a.instrument_root}',file=sys.stderr)
    if a.mode == 'b1-resources':
        if any(x is None for x in (a.before_record, a.after_record, a.before_sha256, a.knife, a.expected_entries, a.retired_entries)):
            raise ValueError('B1 explicit records/before identity/knife/entry sets required')
        result = json.dumps(b1_resources(a.before_record, a.after_record, a.before_sha256,
                            a.expected_entries.split(','), a.retired_entries.split(',') if a.retired_entries else [],
                            a.knife, a.root), sort_keys=True)
    elif a.mode=='frozen':result=frozen(a.root)
    elif a.mode.startswith('prune-'):result=prune_counts(a.root)[['prune-regular','prune-integration','prune-frozen'].index(a.mode)]
    elif a.mode=='b0':result=b0(a.root,a.instrument_root)
    elif a.mode.startswith('s4-'):
        output=Path(tempfile.mkdtemp(prefix='s4-facts-',dir='/tmp')); c=gate.load_c(a.instrument_root)
        if a.mode=='s4-interface':
            c.check_source(a.root,output)
            _, defs, _, _ = c.extract(a.root, output)
            result=c.interface_generation(defs)+'/4/4/4'
        elif a.mode=='s4-widths':result=c.check_attrs_widths(a.root,output)
        elif a.mode=='s4-symbols':result=c.check_old_symbols(a.root)
        elif a.mode=='s4-callers':result=s4_callers(a.root,a.instrument_root)
        elif a.mode=='s4-resources-accepted':result=resources_accepted(a.root)
        elif a.mode=='s4-resources-selftest':result=resource_selftest(output)
        else:
            if any(p is None or not p.is_file() for p in (a.before_log,a.after_log,a.resource_context)):
                raise ValueError('S4 resource raw logs/context required')
            readings=check_resources(a.before_log.read_text(),a.after_log.read_text(),json.loads(a.resource_context.read_text()))
            result=json.dumps({'numeric_pass':True,'entries':readings,'evidence_files':{str(p):gate.sha(p) for p in (a.before_log,a.after_log,a.resource_context)}},sort_keys=True)
    else:
        old,new=test_inventory(a.root,a.instrument_root);result='/'.join(map(str,old)) if a.mode=='historical-inventory' else 1
    print(result)


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        print('B0_FACT_ERROR: '+str(e));sys.exit(1)
