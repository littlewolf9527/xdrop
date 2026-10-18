#!/usr/bin/env python3
"""FF PLAN v1.0: portable dry-run; real execution only in the owned Linux lab."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

KIT = Path(__file__).resolve().parent
DAEMONS, SCRATCH = None, None
CELLS = 'F-ex F-cidr6 F-cond-hit F-cond-miss F-rl F-wl F-miss4 F-miss6 F-arp F-map6 F-crl F-new'.split()
PHASES = ['P1', 'P2', 'P3', 'P4a', 'P4c']
M_SCENES = {'M1': ['inb'], 'M3': ['inb', 'both'], 'M4': ['inb'], 'M5': ['both'], 'M6': ['inb'], 'M7': ['both']}
M_FILES = dict(zip(M_SCENES, ['node/bpf/xdrop_gate.c', 'node/bpf/xdrop_main.c', 'node/agent/main.go', 'node/agent/api/commit.go', 'node/agent/api/sync.go', 'node/agent/api/config.go']))

M_SCENES.update(M8=['inb'], N2=['inb'], N3=['hidx'], N4=[], N5=[], N6=['upg'])
M_FILES = {k:[v] for k,v in M_FILES.items()}
M_FILES.update(M8=['node/bpf/xdrop_main.c'], N2=['node/agent/main.go'], N3=['node/bpf/xdrop_main.c','node/bpf/xdrop_gate.c'], N4=['node/agent/main.go'], N5=['node/agent/main.go'], N6=['node/agent/main.go'])
M_TESTS = {'N4':'TestFFDevmapReconcile', 'N5':'TestFFStartupOrder', 'N6':'TestFFStartupOrder'}
BASELINE = {'upg': 'b9e06b79fe384aba783c692ec88bad3164c81683', 'ctl': 'd39805f4910e4245004cf1157056c0ad749ef379'}
SCENES = ['inb','both','hidx','upg','ctl']

def run(args, cwd=None, env=None):
    return subprocess.run(list(map(str, args)), cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True).stdout

def emit(kind, data):
    print(kind+' '+json.dumps(data, sort_keys=True), flush=True)

def digest(data):
    return hashlib.sha256(data if isinstance(data, bytes) else json.dumps(data, sort_keys=True).encode()).hexdigest()

def verify(a):
    for line in (KIT/'SHA256SUMS').read_text().splitlines():
        want, name = line.split('  ', 1)
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert digest((KIT/name).read_bytes()) == want, 'kit hash: '+name
    manifest = json.loads((KIT/'SOURCE_SHA256.json').read_text())
    assert manifest['baseline'] == a.baseline == BASELINE['upg'], 'baseline differs'
    a.source_head = manifest['head']
    for name, want in manifest['files'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert digest((a.source/name).read_bytes()) == want, 'source hash: '+name
    print('INPUTS_VERIFIED source_files=%d' % len(manifest['files']), flush=True)
    return manifest

def expected(scenes):
    result = {}
    for s in scenes:
        for p in (['P1h'] if s=='hidx' else ['P1u-before','P1u-after'] if s in ['upg','ctl'] else PHASES):
            for d in ['wan_to_lan', 'lan_to_wan']:
                for c in (['F-miss4','F-miss6','F-arp'] if p=='P1h' else CELLS[:11] if p=='P1' else ['F-ex','F-miss4','F-arp'] if p=='P4a' or p.startswith('P1u-') else CELLS):
                    n = 50 if c in ['F-rl','F-crl'] else 20
                    filtered = s != 'hidx' and (s == 'both' or d == 'wan_to_lan')
                    ex = [n, n]
                    if filtered:
                        if c in ['F-rl','F-crl']: ex = [1, 49]
                        elif c in ['F-ex', 'F-cidr6', 'F-cond-hit', 'F-map6', 'F-new'] or (c == 'F-wl' and p != 'P1'): ex = [0, 0]
                    result[s, p, d, c] = (n, ex)
    return result

def count_keys(scenes):
    return {(s, p, i) for s in scenes if s in ['inb','both'] for p in PHASES if p != 'P4a' for i in
            ['R-ex.match_count', 'R-cidr6.match_count', 'R-cond.match_count', 'R-rl.match_count', 'R-crl.match_count', 'whitelisted_packets', 'mapped_v6_dropped', 'rate_limited_packets'] + ([] if p == 'P1' else ['R-new.match_count', 'R-wl.match_count'])}

def allowed(m, key, count=False, positive=False):
    s, p, *tail = key
    if count:
        i = tail[0]
        if m == 'M1': return i == 'mapped_v6_dropped' or (p == 'P1' and i == 'whitelisted_packets')
        if m == 'M3': return False
        if m == 'M4': return s == 'inb'
        if m == 'M5': return p in ['P2', 'P3'] and positive
        if m == 'M6': return i.endswith('.match_count') or i in ['rate_limited_packets', 'mapped_v6_dropped'] or (p == 'P1' and i == 'whitelisted_packets')
        if m == 'M7': return positive
        if m == 'M8': return i == 'rate_limited_packets'
        return False
    d, c = tail
    if m == 'M1': return d == 'lan_to_wan' and c == 'F-map6'
    if m == 'M3': return (s == 'both' or d == 'wan_to_lan') and c in ['F-miss4', 'F-miss6', 'F-cond-miss']
    if m == 'M4': return s == 'inb'
    if m == 'M5': return p in ['P2', 'P3', 'P4a'] and positive
    if m == 'M6': return d == 'lan_to_wan' and ((p == 'P4a' and c == 'F-ex') or (p != 'P4a' and (c in ['F-ex', 'F-cidr6', 'F-cond-hit', 'F-map6', 'F-new', 'F-rl', 'F-crl'] or (p != 'P1' and c == 'F-wl'))))
    if m == 'M7': return positive
    if m == 'M8': return d=='wan_to_lan' and c=='F-crl'
    if m == 'N3': return s=='hidx'
    return False

def must_red(m):
    spec = {'M1': [('inb','P1','lan_to_wan','F-map6')], 'M3': [(s,'P1','wan_to_lan','F-miss4') for s in ['inb','both']],
            'M4': [('inb','P1',d,'F-ex') for d in ['wan_to_lan','lan_to_wan']], 'M5': [('both','P2','wan_to_lan','F-miss4')],
            'M6': [('inb','P1','lan_to_wan','F-ex')], 'M7': [('both','P1','wan_to_lan','F-miss4')]}
    spec.update(M8=[('inb','P1','wan_to_lan','F-crl')], N2=[('inb','postterm','promisc')], N3=[('hidx','HIDX_START_FAIL')], **{k:[('go',v)] for k,v in M_TESTS.items()})
    return set(spec[m])

def tree(path):
    root = Path(path)
    if not root.exists(): return {'exists': False}
    rows = [(str(p.relative_to(root)), p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_size) for p in sorted([root]+list(root.rglob('*')))]
    return {'exists': True, 'count': len(rows), 'sha256': digest(rows)}

def envelope():
    def strip(v):
        if isinstance(v, dict): return {k: strip(x) for k, x in v.items() if not k.endswith('_timer')}
        if isinstance(v, list): return [strip(x) for x in v]
        return v
    links = strip(json.loads(run(['ip','-j','-details','link','show'])))
    tc = {v['ifname']: [run(['tc','-j','qdisc','show','dev',v['ifname']]).decode()]+[run(['tc','-j','filter','show','dev',v['ifname'],d]).decode() for d in ['ingress','egress']] for v in links}
    rows = [r.split(None,4) for r in run(['ps','-eo','pid=,ppid=,etimes=,comm=,args=']).decode().splitlines()]
    procs = [(int(r[0]),int(r[1]),int(r[2]),r[3],r[4] if len(r)>4 else '') for r in rows if len(r)>=4 and r[0]!='2' and r[1]!='2']
    global DAEMONS
    if DAEMONS is None: DAEMONS = sorted((r[0],r[3]) for r in procs if r[1]==1 and r[2]>=3600)
    alive = {(r[0],r[3]) for r in procs}
    leftover = sorted(r[0] for r in procs if str(SCRATCH) in r[4] and r[0] != os.getpid())
    return {'bpffs':tree('/sys/fs/bpf'),'opt':tree('/opt/xdrop'),'link_xdp_sha256':digest(links),'tc_sha256':digest(tc),
            'netns_sha256':digest(run(['ip','netns','list'])),'daemons_sha256':digest([d for d in DAEMONS if d in alive]),'run_leftover':leftover}

def stop_group(p):
    if p is None: return
    try: os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError: p.wait(); return
    deadline = time.monotonic()+15
    while time.monotonic()<deadline:
        p.poll()
        try: os.killpg(p.pid,0)
        except ProcessLookupError: break
        time.sleep(.1)
    else:
        try: os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError: pass
    p.wait()

def cleanup(children, owned):
    errors = []
    for value, fn in [(p,stop_group) for p in children]+[(ns,stop_owned) for ns in owned]:
        try: fn(value)
        except Exception as e: errors.append(type(e).__name__)
    if errors: raise RuntimeError('owned cleanup failed: '+','.join(errors))

def stop_owned(ns):
    pids = run(['ip','netns','pids',ns]).split()
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        for pid in pids:
            try: os.kill(int(pid), sig)
            except ProcessLookupError: pass
        end = time.monotonic()+15
        while pids and time.monotonic()<end:
            time.sleep(.1); pids = run(['ip','netns','pids',ns]).split()
    assert not pids, 'owned process remains'
    run(['ip','netns','delete',ns])

def links():
    rows = [json.loads(run(['ip','-j','-details','link','show','dev',n]))[0] for n in ['w0','l0']]
    return [{'name':r['ifname'],'promisc':'PROMISC' in r['flags'],'xdp':bool(r.get('xdp'))} for r in rows]

def mount_ns_private():
    return os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino

def supervisor_guard(a):
    # 盲审 r1 P1：内部入口，任何挂载前核前提（合法场景 · 父进程传入的宿主 bpffs dev · scratch 已由父进程在工作根下建好 · 已在私有 mount namespace）
    assert a.scene in SCENES and a.host_dev > 0, 'supervisor is internal: --scene/--host-dev required'
    assert a.work_root in a.scratch.parents and a.scratch.is_dir(), 'supervisor scratch must exist under work root'
    assert mount_ns_private(), 'supervisor must run inside a private mount namespace'

def supervisor(a):
    supervisor_guard(a)
    run(['mount','--make-rprivate','/'])
    private, raw, proc, mounted = a.scratch/a.scene/'private', a.scratch/a.scene/'logs', None, False
    try:
        run(['mount','-t','bpf','bpf','/sys/fs/bpf']); mounted = True
        private.mkdir(parents=True, mode=0o700); raw.mkdir(mode=0o700)
        dev = os.stat('/sys/fs/bpf').st_dev != a.host_dev
        fs = run(['stat','-f','-c','%T','/sys/fs/bpf']).strip() == b'bpf_fs'
        assert dev and fs, 'private bpffs witness failed'
        emit('FFMOUNT', {'scenario':a.scene,'dev_different':dev,'fstype_bpf':fs,'pass':dev and fs})
        key = secrets.token_hex(32)
        keyfile, cfg = private/'key', private/'agent-config.example.yaml'
        keyfile.write_text(key); keyfile.chmod(0o600)
        cfg.write_text('server:\n  port: 18080\n  interface: w0\nbpf:\n'+f'  main_path: {a.scratch}/src/node/bpf/xdrop_main.elf\n  gate_path: {a.scratch}/src/node/bpf/xdrop_gate.elf\n'+
                       '  pinning: require\n  xdp_mode: generic\n  rate_limit_divisor: 1\nauth:\n'+f'  node_api_key: "{key}"\nfast_forward:\n  enabled: true\n  pairs:\n    - inbound: w0\n      outbound: l0\n      filter_on: '+('both' if a.scene=='both' else 'inbound')+'\n')
        cfg.chmod(0o600)
        baseline_cfg = private/'baseline-config.example.yaml'
        baseline_cfg.write_text(cfg.read_text().replace(str(a.scratch/'src/node/bpf'),str(a.scratch/(a.scene+'-src/node/bpf')))); baseline_cfg.chmod(0o600)
        env = dict(os.environ, XDROP_FF_SOURCE_HEAD=json.loads((KIT/'SOURCE_SHA256.json').read_text())['head'], XDROP_FF_MUTATION=a.mutation or '', XDROP_FF_GENERATIONS=str(a.out/'generations.json'), XDROP_FF_BASELINE_CONTROLLER=str(a.scratch/(a.scene+'-controller')), XDROP_FF_BASELINE_AGENT=str(a.scratch/(a.scene+'-agent')), XDROP_FF_BASELINE_CONFIG=str(baseline_cfg), XDROP_FF_LAB='1', XDROP_FF_SCENARIO=a.scene, XDROP_CTLCUT2_AGENT=str(a.scratch/'agent'), XDROP_CTLCUT2_AGENT_CONFIG=str(cfg),
                   XDROP_CTLCUT2_KEY_FILE=str(keyfile), XDROP_CTLCUT2_AGENT_URL='http://10.77.0.1:18080', XDROP_CTLCUT2_LOG_DIR=str(raw),
                   XDROP_CTLCUT3_URL='http://10.77.0.1:18081', XDROP_CTLCUT3_CONTROLLER=str(a.scratch/'xdrop-controller'), XDROP_C4A_SECRET_FILE=str(private/'account-secrets.jsonl'))
        command = ['taskset','-c',str(sorted(os.sched_getaffinity(0))[int(a.scene=='both') % len(os.sched_getaffinity(0))]),a.scratch/'api.test','-test.v','-test.timeout=10m','-test.run=^TestFFLab$']
        started, expired = time.monotonic(), False
        with (raw/'process.log').open('wb') as log:
            proc = subprocess.Popen(list(map(str,command)), stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            try: proc.wait(timeout=610)
            except subprocess.TimeoutExpired: expired = True; stop_group(proc)
        stop_group(proc)
        values, proofs = [key], list(raw.glob('*.auth-scan.json'))
        if a.scene!='hidx':
            records = [json.loads(v) for v in (private/'account-secrets.jsonl').read_text().splitlines()]
            assert {r['kind'] for r in records}=={'password','key','secret','token'} and len(proofs)==1, 'account scan coverage'
            values += [r['value'] for r in records]
            proof = json.loads(proofs[0].read_text())
            assert proof['secret_classes']==4 and proof['matches']==0 and all(proof['counts'].get(k,0)>0 for k in ['logs','database','wal','responses']), 'account scan evidence'
        logs = [p for p in raw.rglob('*') if p.is_file()]
        matches = sum(p.read_bytes().count(v.encode()) for p in logs for v in values)
        positive = keyfile.read_bytes().count(key.encode())==1
        emit('FFSECRET', {'scenario':a.scene,'files_checked':len(logs),'secret_classes':1 if a.scene=='hidx' else 5,'matches':matches,'node_positive_control':positive,'pass':matches==0 and positive and len(logs)>0})
        assert matches==0 and positive, 'secret leak; raw logs withheld'
        dest = a.out/a.scene
        shutil.copytree(raw,dest)
        for line in (raw/'process.log').read_text().splitlines():
            if line.startswith('FF'): print(line,flush=True)
        endings = {v:int(subprocess.run(['/usr/bin/grep','-c','^--- '+v+': TestFFLab',raw/'process.log'],capture_output=True).stdout.strip()) for v in ['PASS','FAIL','SKIP']}
        terminal = next((v for v,n in endings.items() if n==1 and sum(endings.values())==1),'MISSING')
        emit('FFEXIT', {'scenario':a.scene,'exit':proc.returncode,'timeout':expired,'test_terminal':terminal,'elapsed_s':time.monotonic()-started})
    finally:
        try: stop_group(proc)
        finally:
            # 盲审 r2 P2：只卸自己挂上的 bpffs（挂载失败时⛔ 卸继承来的挂载、⛔ 盖掉原始错误）
            try:
                if mounted: run(['umount','/sys/fs/bpf'])
            finally: shutil.rmtree(private,ignore_errors=True)

def stamp(value):
    return dt.datetime.fromisoformat(value.replace('Z','+00:00'))

def stream_failures(r):
    """Recompute from measured counts/times; producer booleans must agree."""
    first,last,sig,end,tx,rx,rxend = [stamp(r[k]) for k in ['t_first_send_utc','t_last_send_utc','sigterm_utc','ready_utc','tx_started_utc','rx_started_utc','rx_ended_utc']]
    window = (end-sig).total_seconds()*1000
    pre = bool(r['first_received_send_utc']) and stamp(r['first_received_send_utc'])<sig
    post = bool(r['last_received_send_utc']) and stamp(r['last_received_send_utc'])>end+dt.timedelta(seconds=2)
    cover = rx<=first and rxend>=last+dt.timedelta(seconds=1)
    base = r['sent_unique']>0 and r['send_failures']==0 and first<sig<end and last>end+dt.timedelta(seconds=2) and tx<=first and all(r[k]==0 for k in ['receive_errors','invalid_frames','duplicates']) and r['received_unique']==r['byte_equal'] and 0<=r['received_unique']<=r['sent_unique']
    valid = [0<=r['max_send_gap_ms']<=20, 0<=r['window_sent']<=r['sent_unique'] and r['window_sent']>=0.5*window, cover and pre and post, r['lost_outside_window']==0, r['stats_ok'] is True and r['tp_drops']==0 and 0<=r['max_receive_gap_ms']<=100]
    loss = r['lost']==0 if r['scenario']!='ctl' else r['lost']>0
    # 所有者 10-15：包到了就算过 ⇒ valid[0]（发送间隔 ≤ 20 ms）只记录、不判；漏计丢失由 valid[1] 切换窗口发包量守。
    good = base and all(valid[i] for i in [1,2,4]) and loss and (r['scenario']!='ctl' or valid[3])
    consistent = r['lost']==r['sent_unique']-r['received_unique'] and 0<=r['lost_outside_window']<=r['lost'] and abs(r['window_ms']-window)<0.01 and r['validity']==valid and r['base_valid'] is base and r['pass'] is good and r['pre_received'] is pre and r['post_received'] is post and r['loss_localized'] is valid[3]
    checks = dict(base=base, window=valid[1], coverage=cover, pre=pre, post=post, receive=valid[4], loss=loss)
    if r['scenario']=='ctl': checks['localized'] = valid[3]
    return {k for k,v in checks.items() if not v}, consistent

# 授权单 A1（所有者 D6）：发送连续 ① 只在丢失须为 0 的格承重；断流本身拖慢 veth 发送端，发送空档只会少计丢失。
WAIVED = {('ctl','stream','continuous')}

def stream_allowed(m, item):
    return (item in ['loss','continuous'] and m in ['M3','M5','M7','N6']) or (item=='pre' and m in ['M3','M5','M7']) or (item=='post' and m in ['M3','M7'])

def collect(a, scenes, before, after, restored):
    records = {}
    for file in a.out.glob('supervisor-*.log'):
        for line in file.read_text().splitlines():
            if line.startswith('FF'):
                kind,body = line.split(' ',1); records.setdefault(kind,[]).append(json.loads(body))
    m = a.mutation
    active = [] if m=='N3' else scenes
    ex, rows, counts, failed, invalid = expected(active), {}, {}, set(), []
    for r in records.get('FFCELL',[]):
        k = tuple(r.get(n) for n in ['scenario','phase','dir','cell'])
        if k in rows or k not in ex: invalid.append('duplicate/unknown cell'); continue
        n,e = ex[k]
        fixture = r['sent']==n and r.get('fixture_valid') is True and r.get('invalid_frames')==0 and r['received']==r['byte_equal']
        good = fixture and e[0]<=r['received']<=e[1]
        if r.get('pass') is not good or r.get('expect')!=e or not fixture: invalid.append('cell evidence: '+str(k))
        rows[k] = r
        if not good: failed.add(k)
    for r in records.get('FFCOUNT',[]):
        k = tuple(r.get(n) for n in ['scenario','phase','item'])
        if k in counts or k not in count_keys(active): invalid.append('duplicate/unknown count'); continue
        s,p,i = k; factor = 2 if s=='both' else 1
        want = (50 if i in ['R-rl.match_count','R-crl.match_count'] else 20)*factor
        if i=='whitelisted_packets': want = 20*factor if p=='P1' else 0
        if i=='rate_limited_packets': want = sum(50-rows.get((s,p,d,c),{}).get('received',-1000) for c in ['F-rl','F-crl'] for d in ['wan_to_lan','lan_to_wan'] if s=='both' or d=='wan_to_lan')
        delta = r['after']-r['before']; good = delta==want and r.get('measurement_valid') is True
        if r.get('pass') is not good or r.get('expect')!=want or r.get('delta')!=delta or not r.get('measurement_valid'): invalid.append('count evidence: '+str(k))
        counts[k] = dict(r,verified_pass=good,computed_expect=want)
        if not good: failed.add(k)
    def each(kind, required, predicate):
        rr = records.get(kind,[])
        return len(rr)==len(required) and {r['scenario'] for r in rr}==set(required) and all(predicate(r) for r in rr)
    complete = set(rows)==set(ex) and set(counts)==count_keys(active) and each('FFEND',active,lambda r:r['complete'] is True)
    complete = complete and all(len([r for r in records.get('FFSELECTOR',[]) if r['scenario']==s and r['phase']==p and (p!='P3' or r['before']!=r['after'])])==1 for s in active if s in ['inb','both'] for p in ['P2','P3'])
    paired = records.get('FFPAIR',[])
    for scene in scenes:
        expected_phases = ['P0'] if m=='N3' else ['P0','S']
        selected = [row for row in paired if row['scenario']==scene]
        if {row['phase'] for row in selected}!=set(expected_phases) or len(selected)!=len(expected_phases) or not all(row['selected_sha_match'] and row['source']==(BASELINE['ctl'] if scene=='ctl' else BASELINE['upg'] if scene=='upg' and row['phase']=='P0' else a.source_head+'+ns') for row in selected): invalid.append('selected generation prerequisite')
    shape = each('FFSHAPE',active,lambda r:r['pass'] is True and (r['api_ready'] is True if r['scenario']=='hidx' else r['healthy'] is True) and r['xdp_info']['mode']=='fast_forward' and sorted((v['name'],v['role'],v['attach_mode']) for v in r['xdp_info']['interfaces'])==[('l0','outbound','generic'),('w0','inbound','generic')] and {v['name'] for v in r['links']}=={'w0','l0'} and all(v['promisc'] and v['xdp'] for v in r['links']))
    streamBad = set()
    for r in records.get('FFSTREAM',[]):
        try:
            bad,consistent = stream_failures(r)
            streamBad.update((r['scenario'],'stream',v) for v in bad)
            if not consistent: invalid.append('stream contradictory evidence')
        except (KeyError,ValueError,TypeError): invalid.append('stream malformed')
    complete = complete and each('FFSTREAM',active,lambda r:True)
    for r in records.get('FFPOSTTERM',[]):
        links = r['links']; checked = r['scenario'] in ['inb','both','hidx']
        if {v['name'] for v in links}!={'w0','l0'} or len(links)!=2 or not r['agent_exited'] or r['checked'] is not checked: invalid.append('postterm evidence')
        for item in ['promisc','xdp']:
            good = all(v[item] is True for v in links)
            if r[item] is not good: invalid.append('postterm contradictory evidence')
            if checked and not good: failed.add((r['scenario'],'postterm',item))
    complete = complete and each('FFPOSTTERM',active,lambda r:True) and each('FFPOST',active,lambda r:r['agent_exited'] and len(r['links'])==2 and {v['name'] for v in r['links']}=={'w0','l0'} and all(isinstance(v.get(k),bool) for v in r['links'] for k in ['promisc','xdp']))
    hidx = each('FFHIDX',['hidx'] if 'hidx' in scenes else [],lambda r:r['pass'] is True and (r.get('witness')=='HIDX_START_FAIL' and r.get('exit',0)>0 and r.get('within_30s') is True and r.get('loaded') is True and r.get('devmap_e2big') is True and r.get('health_seen') is False if m=='N3' else r.get('witness')=='HIDX_FORWARD'))
    if m=='N3' and hidx: failed.add(('hidx','HIDX_START_FAIL'))
    testOK = True
    if m in M_TESTS:
        events = [json.loads(line) for line in (a.out/'mutation-tests.jsonl').read_text().splitlines()]
        pkg = 'github.com/littlewolf9527/xdrop/node/agent'; name = M_TESTS[m]
        terminals = [e for e in events if e.get('Test')==name and e.get('Action') in ['pass','fail','skip']]
        testOK = len(terminals)==1 and terminals[0]['Action']=='fail' and terminals[0]['Package']==pkg and any(e.get('Test')==name and e.get('Action')=='run' for e in events)
        testOK = testOK and not any(e.get('Action') in ['fail','skip'] and e.get('Test') and e['Test']!=name for e in events)
        if testOK: failed.add(('go',name))
    parallel = None
    if {'inb','both'}<=set(active):
        bounds = [(min((stamp(r['t_first_send_utc']) for k,r in rows.items() if k[0]==s and k[1]=='P1' and r['t_first_send_utc']),default=None),max((stamp(r['t_last_recv_utc']) for k,r in rows.items() if k[0]==s and k[1]=='P4c' and r['t_last_recv_utc']),default=None)) for s in ['inb','both']]
        parallel = False
        if all(x is not None for b in bounds for x in b):
            lo,hi = max(x[0] for x in bounds),min(x[1] for x in bounds)
            parallel = lo<hi and all(any(lo<=stamp(r['t_complete_utc'])<=hi for k,r in rows.items() if k[0]==s) and any(r['scenario']==s and r['alive'] and lo<=stamp(r['t_utc'])<=hi for r in records.get('FFALIVE',[])) for s in ['inb','both'])
    mount = each('FFMOUNT',scenes,lambda r:r['pass'] is True and r['dev_different'] and r['fstype_bpf']) and all(len([r for r in records.get('FFALIVE',[]) if r['scenario']==s and r.get('event')=='start' and r.get('same_mount') is True])==(1 if m=='N3' else 2) for s in scenes)
    secret = each('FFSECRET',scenes,lambda r:r['pass'] is True and r['matches']==0 and r['files_checked']>0 and r['node_positive_control'] and r['secret_classes']==(1 if r['scenario']=='hidx' else 5))
    def exitOK(r):
        red = any(k[0]==r['scenario'] for k in failed|streamBad)
        return not r['timeout'] and r['test_terminal']==('FAIL' if red else 'PASS')
    exits = each('FFEXIT',scenes,exitOK)
    envelopeOK = bool(before) and before==after and not after['run_leftover']
    failed |= streamBad
    complete = complete and not invalid
    gates = dict(G1=complete and shape and not any(len(k)==4 for k in failed),G2=complete and all(r['verified_pass'] for r in counts.values()),G3=complete and not any(k[0]!='ctl' and len(k)==3 and k[1] in ['stream','postterm'] for k in failed),G4=(complete and not any(k[0]=='ctl' for k in streamBad-WAIVED)) if 'ctl' in active else None,G5=parallel,G6=None,G7=None,G8=None,G9=envelopeOK,G10=mount and secret,G11=None)
    functional = [k for k in expected(scenes) if k[0]!='ctl']
    print('FF_RESULTS expected=%d present=%d pass=%d' % (len(functional),sum(k in rows for k in functional),sum(k in rows and k not in failed for k in functional)),flush=True)
    mutation_ok = None
    if m:
        outside = []
        must = must_red(m)
        for k in failed:
            if k in must: continue
            if len(k)==3 and k[1]=='stream' and stream_allowed(m,k[2]): continue
            if len(k)==4 and allowed(m,k,positive=ex[k][1][1]>0): continue
            if k in counts and allowed(m,k,count=True,positive=counts[k]['computed_expect']>0): continue
            outside.append(k)
        hit = len(must & failed)
        mutation_ok = complete and shape and hidx and exits and mount and secret and envelopeOK and restored and testOK and parallel is not False and hit==len(must) and not outside
        print('MUTATION %s must_red_hit=%d/%d outside_allowed=%d verdict=%s' % (m,hit,len(must),len(outside),'RED_OK' if mutation_ok else 'FAIL'),flush=True)
        gates['G6'] = mutation_ok
    for name,value in gates.items(): print('%s %s' % (name,'PENDING external/other-round evidence' if value is None else 'PASS' if value else 'FAIL'),flush=True)
    report = dict(gates=gates,complete=complete,expected=len(functional),records=records,invalid=invalid,failures=sorted(failed),restored=restored,mutation=m,test_evidence=testOK,exits=exits,hidx=hidx)
    (a.out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    return mutation_ok if m else all([complete,shape,hidx,exits,mount,secret,envelopeOK,parallel,not failed-WAIVED,set(scenes)==set(SCENES)])

def dry(a):
    steps = ['verify source/kit SHA; upg baseline-src=b9e06b7, ctl-src=d39805f; copy into guarded new scratch/out', 'build three paired generations with their Makefiles and same Go commands; all node vendor REF=node-vendor; src controller REF=controller-vendor; upg/ctl controller REF=controller-vendor-old if present, else controller-vendor; no downloads',
             'apply function-scoped mutation in scratch; rebuild BPF and require changed ELF SHA; N4/N5/N6 go test -json named fail events',
             'capture host envelope; private netns/bpffs for each scene; inb/both parallel, then hidx/upg/ctl',
             'P0 shape; R-crl plus existing rules; inb/both P1=22 P2/P3/P4c=24 each P4a=6; 200 cells and 76 counts',
             'S: independent AF_PACKET socket, stats reset/read, 1000 pps across SIGTERM, exit, P4a, fresh T+2s and 1s drain',
             'hidx 40-43: 6 cells, API 200 readiness; upg 12 cells, baseline to new; ctl baseline to baseline loss>0',
             'scan all scene secrets before publishing; owned process/netns cleanup; restore source SHA; compare envelope and fixed collections',
             'one NS regression round; external verifier / g8kit / facts remain required']
    for i,step in enumerate(steps,1): print('%02d. %s' % (i,step))
    if a.list_cells:
        for k,(n,e) in expected(SCENES[:-1]).items(): emit('EXPECTED_CELL',dict(zip(['scenario','phase','dir','cell'],k),sent=n,expect=e))
        print('EXPECTED_COUNTS inb_both_cells=200 hidx_cells=6 upg_cells=12 counters=76 ctl_additional_cells=12')
    print(run([sys.executable,KIT/'selfcheck.py','--source',a.source,'--frames','--oracles']).decode(),end='')
    print('DRY_RUN steps_complete=1 network_calls=0 mounts=0 agent_starts=0')

def main():
    p = argparse.ArgumentParser()
    for name in ['source','scratch','out']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--baseline-src',type=Path); p.add_argument('--ctl-src',type=Path); p.add_argument('--work-root',type=Path,default=Path('/root/xdrop-lab')); p.add_argument('--baseline',required=True); p.add_argument('--ref',type=Path,default=Path('/root/xdrop-lab/ref/labkit-delivery1'))
    p.add_argument('--only',default=','.join(SCENES)); p.add_argument('--mutation',choices=list(M_SCENES)); p.add_argument('--dry-run',action='store_true'); p.add_argument('--list-cells',action='store_true')
    p.add_argument('--supervisor',action='store_true',help=argparse.SUPPRESS); p.add_argument('--scene',help=argparse.SUPPRESS); p.add_argument('--host-dev',type=int,default=0,help=argparse.SUPPRESS)
    a = p.parse_args()
    for name in ['source','scratch','out','ref','work_root']: setattr(a,name,getattr(a,name).resolve())
    a.only = a.only.split(','); assert set(a.only)<=set(SCENES) and len(set(a.only))==len(a.only)
    if a.mutation: a.only = M_SCENES[a.mutation]
    if a.dry_run: verify(a); dry(a); return
    assert sys.platform=='linux' and os.geteuid()==0, 'owned Linux lab root required'
    if a.supervisor: supervisor(a); return
    manifest = verify(a)
    old_sources = {scene: path.resolve() for scene,path in [('upg',a.baseline_src),('ctl',a.ctl_src)] if path is not None}
    for scene in {'upg','ctl'} & set(a.only):
        assert scene in old_sources, '--baseline-src (FF) and --ctl-src (pre-FF) required'
        path = old_sources[scene]
        assert run(['git','-C',path,'rev-parse','HEAD']).decode().strip()==BASELINE[scene]
        assert not run(['git','-C',path,'diff','HEAD','--','node/agent','node/bpf','controller']), 'old generation dirty'
        assert all(path!=x and path not in x.parents and x not in path.parents for x in [a.scratch,a.out])
    assert not a.scratch.exists() and not a.out.exists(), 'scratch/output must be new'
    assert all(a.work_root in x.parents for x in [a.scratch,a.out]), 'lab work root required'
    assert all(x!=y and x not in y.parents and y not in x.parents for x,y in [(a.source,a.scratch),(a.source,a.out),(a.scratch,a.out),(a.ref,a.scratch),(a.ref,a.out)])
    global SCRATCH
    SCRATCH = a.scratch
    a.scratch.mkdir(mode=0o700); a.out.mkdir(mode=0o700)
    for name in ['tmp','gocache']: (a.scratch/name).mkdir(mode=0o700)
    env = dict(os.environ,TMPDIR=str(a.scratch/'tmp'),GOTMPDIR=str(a.scratch/'tmp'),GOCACHE=str(a.scratch/'gocache'),GOPROXY='off',GOTOOLCHAIN='local',GOFLAGS='-mod=vendor',PYTHONDONTWRITEBYTECODE='1')
    os.environ.update(env)
    src, owned, children, before, original, restored = a.scratch/'src', [], [], None, None, True
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for name in manifest['files']:
            dest = src/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(a.source/name,dest)
        for mod,vendor in [('node/agent','node-vendor'),('controller','controller-vendor')]: shutil.copytree(a.ref/vendor,src/mod/'vendor')
        (a.out/'make-baseline.log').write_bytes(run(['make','-B','-C',src/'node/bpf'],env=env))
        baseline = {n:digest((src/'node/bpf'/n).read_bytes()) for n in ['xdrop_main.elf','xdrop_gate.elf']}
        generations = {}
        for scene,oldpath in old_sources.items():
            oldsrc = a.scratch/(scene+'-src')
            names = run(['git','-C',oldpath,'ls-files','--','node/agent','node/bpf','controller']).decode().splitlines()
            for name in names:
                if Path(name).name in ['config.yaml','INFRASTRUCTURE.md'] or (oldpath/name).is_symlink(): continue
                dest = oldsrc/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(oldpath/name,dest)
            old_controller_vendor = 'controller-vendor-old' if (a.ref/'controller-vendor-old').is_dir() else 'controller-vendor'
            for mod,vendor in [('node/agent','node-vendor'),('controller',old_controller_vendor)]: shutil.copytree(a.ref/vendor,oldsrc/mod/'vendor')
            assert (oldsrc/'node/bpf/Makefile').read_bytes()==(src/'node/bpf/Makefile').read_bytes()
            (a.out/(scene+'-make.log')).write_bytes(run(['make','-B','-C',oldsrc/'node/bpf'],env=env))
            static = a.scratch/(scene+'-index.html'); static.write_text('<!doctype html><title>FF headless fixture</title>')
            overlay = a.scratch/(scene+'-overlay.json'); overlay.write_text(json.dumps({'Replace':{str(oldsrc/'controller/web/dist/index.html'):str(static)}}))
            for role,mod,target,cgo in [('agent','node/agent','.','0'),('controller','controller','./cmd/xdrop-controller','1')]:
                binary = a.scratch/(scene+'-'+role)
                buildenv = dict(env,CGO_ENABLED=cgo,GOFLAGS=env['GOFLAGS']+(' -overlay='+str(overlay) if role=='controller' else ''))
                (a.out/(scene+'-'+role+'-build.log')).write_bytes(run(['go','build','-o',binary,target],cwd=oldsrc/mod,env=buildenv))
                generations[str(binary)] = {'source':BASELINE[scene], 'sha':digest(binary.read_bytes())}
        if a.mutation:
            original = {name:(src/name).read_bytes() for name in M_FILES[a.mutation]}
            (a.out/'mutation-anchor.log').write_bytes(run([sys.executable,KIT/'selfcheck.py','--source',src]))
            (a.out/'patch.log').write_bytes(run(['patch','-p1','-i',KIT/'mutations'/(a.mutation+'.patch')],cwd=src))
            (a.out/'make-mutation.log').write_bytes(run(['make','-B','-C',src/'node/bpf'],env=env))
            for name in M_FILES[a.mutation]:
                if name.endswith('.c'):
                    elf = Path(name).stem+'.elf'
                    assert digest((src/'node/bpf'/elf).read_bytes())!=baseline[elf], 'mutated ELF unchanged'
            if a.mutation in M_TESTS:
                result = subprocess.run(['go','test','-json','-tags','integration','-count=1','-run','^'+M_TESTS[a.mutation]+'$','.'],cwd=src/'node/agent',env=dict(env,CGO_ENABLED='0'),capture_output=True)
                (a.out/'mutation-tests.jsonl').write_bytes(result.stdout); (a.out/'mutation-tests-stderr.log').write_bytes(result.stderr)
        (a.out/'elf-hashes.json').write_text(json.dumps({'baseline':baseline,'built':{n:digest((src/'node/bpf'/n).read_bytes()) for n in baseline}},indent=2))
        commands = [('agent',src/'node/agent',['go','build','-o',a.scratch/'agent','.'],'0'),('controller',src/'controller',['go','build','-o',a.scratch/'xdrop-controller','./cmd/xdrop-controller'],'1'),('api',src/'controller',['go','test','-c','-o',a.scratch/'api.test','./core/api'],'1'),('vet',src/'controller',['go','vet','./core/api/'],'1')]
        for name,cwd,cmd,cgo in commands:
            buildenv = dict(env,CGO_ENABLED=cgo)
            (a.out/(name+'-build.log')).write_bytes(run(cmd,cwd=cwd,env=buildenv))
        for binary in [a.scratch/'agent',a.scratch/'xdrop-controller']: generations[str(binary)] = {'source':a.source_head+'+ns', 'sha':digest(binary.read_bytes())}
        (a.out/'generations.json').write_text(json.dumps(generations,sort_keys=True))
        skipenv = dict(env); skipenv.pop('XDROP_FF_LAB',None)
        skip = run([a.scratch/'api.test','-test.v','-test.run=^TestFFLab$'],env=skipenv); (a.out/'linux-skip.log').write_bytes(skip)
        assert run(['/usr/bin/grep','-c','^--- SKIP: TestFFLab',a.out/'linux-skip.log']).strip()==b'1' and b'FAIL' not in skip
        print('BUILD Linux vet=0 skip=1 fail=0',flush=True)
        before = envelope(); (a.out/'envelope-before.json').write_text(json.dumps(before,indent=2))
        for s in a.only:
            if s not in ['inb','both']:
                for child in children: child.wait(timeout=650)
            ns = 'ff-'+s+'-'+secrets.token_hex(6); run(['ip','netns','add',ns]); owned.append(ns)
            (a.out/'owned-netns.txt').write_text('\n'.join(owned)+'\n')
            pre = ['ip','netns','exec',ns]
            run(pre+['sysctl','-qw','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'])
            run(['ip','-n',ns,'link','set','lo','up']); run(['ip','-n',ns,'addr','add','10.77.0.1/32','dev','lo'])
            base = 40 if s=='hidx' else 2
            for i,(x,y) in enumerate([('w0','w1'),('l0','l1')]): run(['ip','-n',ns,'link','add',x,'index',base+2*i,'type','veth','peer','name',y,'index',base+2*i+1])
            for i,n in enumerate(['w0','w1','l0','l1']): run(['ip','-n',ns,'link','set',n,'address','02:00:00:00:0f:%02x'%(i+1),'up'])
            actual = json.loads(run(['ip','-n',ns,'-j','link','show']))
            assert {r['ifname']:r['ifindex'] for r in actual}=={'lo':1,**{n:base+i for i,n in enumerate(['w0','w1','l0','l1'])}}
            (a.out/(s+'-topology.json')).write_text(json.dumps(actual,indent=2))
            with (a.out/('supervisor-'+s+'.log')).open('wb') as log:
                cmd = pre+['unshare','--mount','--',sys.executable,KIT/'runner.py','--supervisor','--scene',s,'--source',a.source,'--baseline',a.baseline,'--scratch',a.scratch,'--out',a.out,'--work-root',a.work_root,'--host-dev',str(os.stat('/sys/fs/bpf').st_dev)]+(['--mutation',a.mutation] if a.mutation else [])
                children.append(subprocess.Popen(list(map(str,cmd)),stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        for child in children: child.wait(timeout=650)
    finally:
        try:
            try:
                cleanup(children,owned)
            finally:
                if original is not None:
                    for name,data in original.items(): (src/name).write_bytes(data)
                    restored = all(digest((src/name).read_bytes())==digest(data) for name,data in original.items())
                    emit('FFRESTORE', {'equal':restored,'files':{n:digest(v) for n,v in original.items()}})
        finally:
            try:
                if before is not None:
                    after = envelope(); (a.out/'envelope-after.json').write_text(json.dumps(after,indent=2))
                    ok = collect(a,a.only,before,after,restored)
                    if not ok: raise RuntimeError('FF gates failed; inspect machine results')
            finally: shutil.rmtree(a.scratch)

if __name__=='__main__': main()
