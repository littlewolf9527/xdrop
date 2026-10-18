#!/usr/bin/env python3
"""B0 synthetic case specification and independent result consumer.

No production sorting/masking helper or tested table supplies expected winners.
The field incidence authority is the frozen F-067 roster at bd686710.
"""
import copy
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import re
import struct

AUTH = (0x0000000261E66F01, 0x00000003E670341F, 0x00000003FF868043,
        0x0000000399F15887, 0x000000015555E22F)
ACTIVE = tuple(n for n in range(34) if n not in (19, 20, 32))
STAGES = ('exact', 'cidr', 'anomaly_exact', 'anomaly_cidr')
ALL_STAGES = ('whitelist',) + STAGES
VARIANTS = ('dual', 'single-a', 'single-b', 'bitmap-a', 'bitmap-b', 'map-miss-a', 'map-miss-b',
            'length-a', 'length-b', 'flags-a', 'flags-b', 'anomaly-a', 'anomaly-b')
SCHEMA = 'xdrop-s2b-competition-v1'
SOURCE_COMMIT = 'b07a004950e2f813545db540599767e2a4dc214e'
SOURCE_HASHES = {
    's2a': {'node/bpf/xdrop_main.c': 'e1404a7a53bad29edb787ecab88d2bd3e80b7eddf94fc7859d9ab7ca3867654a',
            'node/bpf/combo_masks.h': '0246f4655ea2cad3adfa958112a6db800d05705064efc634a5360796e92318f5'},
    's2b': {'node/bpf/xdrop_main.c': '2a111fa26dc87b5bcd90fd26405edc290ee281375208041775d48650d34b2c32',
            'node/bpf/combo_masks.h': 'b296d4d1798f7fdff7d0b42484e38bbab930e57ed499510a63f1fe5dc3470172'},
}
COMMON_HASHES = {'node/bpf/xdrop.h': 'd1dd8269ab0dfb0923e565fe075f830f652e150b0e741f9869d1231d967833d2',
                 'node/bpf/xdrop_gate.c': 'a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199',
                 'node/bpf/headers/bpf_helpers.h': 'ac22dae8c99e5702073d8ecd9fc75beb9fc29c67a2a1face4211cca579ba2d13'}


class CaseError(ValueError):
    pass


def mask(n):
    return sum(1 << i for i, incidence in enumerate(AUTH) if incidence & (1 << n)) if n in ACTIVE else 0


def ordered(contract, stage='exact'):
    if contract not in ('s2a', 's2b'):
        raise CaseError('explicit known contract required')
    return list(ACTIVE) if contract == 's2a' or stage == 'whitelist' else sorted(ACTIVE, key=lambda n: (-bin(mask(n)).count("1"), n))


def source_identity(root, contract):
    if contract not in SOURCE_HASHES or not Path(root).is_absolute():
        raise CaseError('explicit absolute source root and known contract required')
    root = Path(root).resolve(strict=True)
    files = {}
    for rel, expected in dict(COMMON_HASHES, **SOURCE_HASHES[contract]).items():
        path = (root / rel).resolve(strict=True)
        if not path.is_relative_to(root):
            raise CaseError('source escapes root: ' + rel)
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise CaseError(f'{contract} source identity: {rel} {digest} != {expected}')
        files[rel] = {'path': str(path), 'sha256': digest}
    return {'root': str(root), 'source_commit': SOURCE_COMMIT if contract == 's2a' else SOURCE_COMMIT + '+working-tree', 'contract': contract, 'files': files}


def check_order_header(text):
    s = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    tables = re.findall(r'static\s+const\s+__u8\s+combo_order\[\]\s*=\s*\{([^{}]*)\}\s*;', s, re.S)
    if len(tables) != 1 or len(re.findall(r'\bcombo_order\s*\[\s*\]\s*=', s)) != 1:
        raise CaseError('S2b order definitions must be exactly one')
    if re.findall(r'^#define\s+COMBO_ORDER_LEN\s+(.+)$', s, re.M) != ['(sizeof(combo_order) / sizeof(combo_order[0]))']:
        raise CaseError('S2b order length must use actual sizeof')
    values = tables[0].split(',')
    if values[-1].strip():
        raise CaseError('S2b order trailing delimiter missing')
    values = values[:-1]
    if any(not re.fullmatch(r'\s*-?\d+\s*', v) for v in values):
        raise CaseError('S2b unknown order syntax')
    actual = [int(v) for v in values]
    if any(v < 0 or v >= 34 for v in actual):
        raise CaseError('S2b order range')
    if len(actual) != len(set(actual)):
        raise CaseError('S2b duplicate order entry')
    if any(v not in ACTIVE for v in actual):
        raise CaseError('S2b retired order entry')
    if set(actual) != set(ACTIVE):
        raise CaseError('S2b order identity set')
    # Pairwise comparator independent of the generator's sorting call.
    for i in range(len(actual)-1):
        a, b = actual[i:i+2]
        wa, wb = sum(bool(f & (1 << a)) for f in AUTH), sum(bool(f & (1 << b)) for f in AUTH)
        if wa < wb or wa == wb and a >= b:
            raise CaseError(f'S2b K order at {i}: {a} before {b}')
    return actual


def packet():
    return {'Src': '192.0.2.10', 'Dst': '198.51.100.20', 'Sport': 1234, 'Dport': 443,
            'Proto': 6, 'Length': 64, 'Flags': 16, 'Anomaly': 2}


def key_for(n, p, cidr=False):
    fields = ('SrcID', 'DstID', 'Sport', 'Dport', 'Proto') if cidr else ('Src', 'Dst', 'Sport', 'Dport', 'Proto')
    values = (101, 202, p['Sport'], p['Dport'], p['Proto']) if cidr else tuple(p[k] for k in fields)
    return {k: (v if mask(n) & (1 << i) else ('' if k in ('Src', 'Dst') else 0)) for i, (k, v) in enumerate(zip(fields, values))}


def wire(key, cidr=False):
    if cidr:
        return (struct.pack('<II', key['SrcID'], key['DstID']) + struct.pack('!HHB', key['Sport'], key['Dport'], key['Proto']) + b'\0'*3).hex()
    def ip(s):
        return b'\0'*10+b'\xff\xff'+ipaddress.IPv4Address(s).packed if s else b'\0'*16
    return (ip(key['Src'])+ip(key['Dst'])+struct.pack('!HHB',key['Sport'],key['Dport'],key['Proto'])+b'\0'*3).hex()


def wire_value(r):
    b = bytearray(32)
    b[:4] = bytes([2 if r['Rate'] else 1, r['FlagsMask'], r['FlagsValue'], r['Anomaly']])
    struct.pack_into('<I',b,4,r['Rate']);struct.pack_into('<HH',b,24,r['MinLength'],r['MaxLength'])
    return b.hex()


def rule(n, p, stage, label, rate=0):
    cidr = 'cidr' in stage
    k = key_for(n,p,cidr)
    return {'ID': label, 'Combo': n, 'Key': {} if cidr else k, 'CIDRKey': k if cidr else {},
            'MinLength':0, 'MaxLength':0, 'FlagsMask':0, 'FlagsValue':0,
            'Anomaly':2 if 'anomaly' in stage else 0, 'Rate':rate,
            'WireKey':wire(k,cidr)}


def blank_rules():
    return {'Whitelist':[], 'Exact':[], 'CIDR':[],
            'SrcPrefixes':[{'Network':'192.0.2.0/24','ID':101}],
            'DstPrefixes':[{'Network':'198.51.100.0/24','ID':202}]}


def group(stage):
    return 'Whitelist' if stage == 'whitelist' else ('CIDR' if 'cidr' in stage else 'Exact')


def relation(a, b):
    if a == b:return 'singleton'
    a,b=min(a,b),max(a,b)
    ma,mb=mask(a),mask(b)
    wa,wb=bin(ma).count('1'),bin(mb).count('1')
    if wa==wb:return 'unchanged-tie'
    if wa>wb:return 'unchanged-weight'
    return 'reversed-containment' if ma & mb == ma else 'reversed-incomparable'


def make_case(a, b, stage, variant):
    p=packet();rs=blank_rules();g=group(stage)
    rules=[rule(a,p,stage,'a',0),rule(b,p,stage,'b',0 if 'anomaly' in stage or stage=='whitelist' else 1000)]
    bitmap=(1<<a)|(1<<b)
    if variant=='swap-actions':rules[0]['Rate'],rules[1]['Rate']=rules[1]['Rate'],rules[0]['Rate']
    if variant in ('single-a','bitmap-a'):bitmap=1<<a
    if variant in ('single-b','bitmap-b'):bitmap=1<<b
    if variant in ('single-a','map-miss-b'):rules=rules[:1]
    if variant in ('single-b','map-miss-a'):rules=rules[1:]
    for which,idx in [('a',0),('b',1)]:
        if variant=='length-'+which:rules[idx]['MinLength']=65
        if variant=='flags-'+which:rules[idx]['FlagsMask']=2;rules[idx]['FlagsValue']=2
        if variant=='anomaly-'+which:rules[idx]['Anomaly']=1
    rs[g]=rules
    return {'pair_id':f'{a:02d}-{b:02d}', 'pair_relation':relation(a,b), 'stage':stage, 'variant':variant,
            'packet':p, 'rules':rs, 'bitmaps':{'Whitelist':bitmap if g=='Whitelist' else 0,'Exact':bitmap if g=='Exact' else 0,'CIDR':bitmap if g=='CIDR' else 0},
            'lpm_expected':[101,202], 'c_replay':stage in STAGES}


def cases():
    result=[]
    for a,b in itertools.combinations(ACTIVE,2):
        for stage in STAGES:
            for variant in VARIANTS + (() if 'anomaly' in stage else ('swap-actions',)):
                result.append(make_case(a,b,stage,variant))
        result.append(make_case(a,b,'whitelist','dual'))
    for n in ACTIVE:
        for stage in ALL_STAGES:
            row=make_case(n,n,stage,'single-a');row['pair_id']=f'single-{n:02d}';result.append(row)
    for stage in STAGES:
        for variant in ('all-miss','zero-bitmap','no-lpm','no-anomaly'):
            row=make_case(5,24,stage,'dual');row['pair_id']='control';row['variant']=variant
            if variant=='all-miss':row['rules'][group(stage)]=[]
            if variant=='zero-bitmap':row['bitmaps'][group(stage)]=0
            if variant=='no-lpm':row['rules']['SrcPrefixes']=[];row['rules']['DstPrefixes']=[];row['lpm_expected']=[0,0];row['c_replay']=False
            if variant=='no-anomaly':row['packet']['Anomaly']=0;row['c_replay']=not stage.startswith('anomaly')
            result.append(row)
    for first,second in [('whitelist','exact'),('exact','cidr'),('cidr','anomaly_exact'),('anomaly_exact','anomaly_cidr')]:
        row=make_case(5,24,first,'single-a');row['pair_id']='cross';row['variant']=first+'-before-'+second;row['stage']=first+'>'+second;row['c_replay']=False
        row['rules'][group(second)].append(rule(24,row['packet'],second,'later',0));row['bitmaps'][group(second)]|=1<<24
        result.append(row)
    # The exact existing fixture: UDP protocol-only DROP versus src/ports/UDP RATE.
    row=make_case(5,24,'exact','dual');row['pair_id']='anchor';row['variant']='1-priority';row['packet']['Proto']=17;row['packet']['Flags']=0
    row['rules']['Exact']=[rule(5,row['packet'],'exact','coarse-drop'),rule(24,row['packet'],'exact','fine-rate',1000)];result.append(row)
    result.extend(width_cases())
    return result


def width_cases():
    """A width-discriminating exact/CIDR pair; length is absent from key identity."""
    result = []
    for stage in ('exact', 'cidr'):
        row = make_case(5, 24, stage, 'single-a')
        row['pair_id'] = 'width-256'
        row['variant'] = 'length-256-min-256'
        row['packet']['Length'] = 256
        row['rules'][group(stage)][0]['MinLength'] = 256
        result.append(row)
    return result


def identity(row):
    return (row['pair_id'],row['stage'],row['variant'])


def no_match():
    return {'Stage':'none','Combo':-1,'RuleID':'','Action':'pass_no_match'}


def lpm(row):
    out=[]
    for side in ('Src','Dst'):
        candidates=[q for q in row['rules'][side+'Prefixes'] if ipaddress.ip_address(row['packet'][side]) in ipaddress.ip_network(q['Network'])]
        out.append(max(candidates,key=lambda q:ipaddress.ip_network(q['Network']).prefixlen)['ID'] if candidates else 0)
    return out


def qualifies(r,p,stage):
    return (not r['MinLength'] or p['Length']>=r['MinLength']) and (not r['MaxLength'] or p['Length']<=r['MaxLength']) and (p['Proto']!=6 or not r['FlagsMask'] or p['Flags']&r['FlagsMask']==r['FlagsValue']) and (bool(r['Anomaly']&p['Anomaly']) if stage.startswith('anomaly') else r['Anomaly']==0)


def decision(row, contract):
    p=row['packet'];srcid,dstid=lpm(row)
    for stage in ALL_STAGES:
        if stage.startswith('anomaly') and not p['Anomaly']:continue
        cidr='cidr' in stage
        if cidr and not (srcid or dstid):continue
        eligible=[]
        for r in row['rules'][group(stage)]:
            n=r['Combo']
            if not row['bitmaps'][group(stage)]&(1<<n):continue
            want=key_for(n,p,cidr)
            if cidr:
                if not srcid:want['SrcID']=0
                if not dstid:want['DstID']=0
            if r['CIDRKey' if cidr else 'Key']!=want:continue
            if stage!='whitelist' and not qualifies(r,p,stage):continue
            eligible.append(r)
        if eligible:
            # Independent scalar comparator; never a tested order table.
            win=min(eligible,key=lambda q:(0 if contract=='s2a' or stage=='whitelist' else -sum(bool(f&(1<<q['Combo'])) for f in AUTH),q['Combo']))
            action='pass_whitelist' if stage=='whitelist' else ('rate_limit@'+str(win['Rate']) if win['Rate'] and not stage.startswith('anomaly') else 'drop')
            return {'Stage':stage,'Combo':win['Combo'],'RuleID':win['ID'],'Action':action}
    return no_match()


def c_input(row, *, fallback=0, override=None, cfg=1, selector=0):
    stage=row['stage'];p=row['packet'];cidr='cidr' in stage
    k=key_for(0,p,cidr)
    if cidr:k['SrcID'],k['DstID']=lpm(row)
    rs=row['rules'][group(stage)]
    stage_num={'exact':0,'anomaly_exact':1,'cidr':2,'anomaly_cidr':3}[stage]
    parts=[stage_num,row['bitmaps'][group(stage)],p['Length']<<8|p['Flags'],p['Anomaly'],selector,fallback,int(override is not None),override or 0,cfg,wire(k,cidr),len(rs)]
    for rule_ in rs:parts.extend([rule_['WireKey'],wire_value(rule_)])
    return ' '.join(map(str,parts))+'\n'


def check_c(row, contract, actual, *, fallback=False, override=None, cfg=True, selector=0):
    stage=row['stage'];rs=row['rules'][group(stage)];p=row['packet'];bm=((1<<64)-1 if fallback else row['bitmaps'][group(stage)])
    probes=[];winner=-1
    seq=list(range(34)) if contract=='s2a' else ordered(contract)
    if cfg and override is None:
        for pos,n in enumerate(seq):
            if n not in ACTIVE or not bm&(1<<n):continue
            key=wire(key_for(n,p,'cidr' in stage),'cidr' in stage)
            hit=next((i for i,q in enumerate(rs) if q['WireKey']==key),-1)
            probes.append({'position':pos,'selector':selector,'hit':hit,'key':key})
            if hit>=0 and qualifies(rs[hit],p,stage):winner=hit;break
    expect={'winner':winner,'new':int(cfg),'destroy':int(cfg),'probes':probes}
    if actual!=expect:
        axis='probe/key trajectory' if actual.get('probes')!=probes else ('destroy path' if actual.get('destroy')!=int(cfg) else 'winner')
        raise CaseError(f'C {axis} {identity(row)}: actual={actual} expected={expect}')
    return no_match() if winner<0 else {'Stage':stage,'Combo':rs[winner]['Combo'],'RuleID':rs[winner]['ID'],
                                        'Action':'rate_limit@'+str(rs[winner]['Rate']) if rs[winner]['Rate'] and not stage.startswith('anomaly') else 'drop'}


def validate_case_set(rows):
    if type(rows) is not list:raise CaseError('case rows must be list')
    wanted={identity(r):r for r in cases()}
    seen=set()
    for row in rows:
        if type(row) is not dict:raise CaseError('case row must be object')
        key=identity(row)
        if key in seen:raise CaseError('duplicate case identity: '+str(key))
        seen.add(key)
        if key not in wanted or not same_types(row,wanted[key]) or row!=wanted[key]:raise CaseError('case specification differs: '+str(key))
        if lpm(row)!=row['lpm_expected']:raise CaseError('LPM identity differs: '+str(key))
        for g in ('Whitelist','Exact','CIDR'):
            keys=[q['WireKey'] for q in row['rules'][g]]
            if len(keys)!=len(set(keys)):raise CaseError('duplicate rule map key: '+str(key))
    if seen!=set(wanted):raise CaseError(f'case identity set differs: actual={len(seen)} expected={len(wanted)} missing={sorted(set(wanted)-seen)[:3]}')
    return wanted


def same_types(actual, expected):
    if type(actual) is not type(expected):return False
    if type(expected) is dict:return set(actual)==set(expected) and all(same_types(actual[k],v) for k,v in expected.items())
    if type(expected) is list:return len(actual)==len(expected) and all(same_types(a,b) for a,b in zip(actual,expected))
    return True


def validate_report(report, expected_sources, required_execution):
    if type(report) is not dict or set(report)!= {'schema','sources','instrument','execution','rows'}:raise CaseError('report schema fields')
    if report['schema']!=SCHEMA:raise CaseError('unknown report schema')
    if report['sources']!=expected_sources:raise CaseError('report source identity')
    if report['execution']!=required_execution:raise CaseError('report execution identities/RC')
    if type(report['instrument']) is not dict or not report['instrument']:raise CaseError('instrument identity missing')
    if type(report['rows']) is not list:raise CaseError('report rows must be list')
    base_fields=set(cases()[0]);outputs={'before_expected','before_actual','after_expected','after_actual','before_c','after_c'}
    plain=[]
    for row in report['rows']:
        if type(row) is not dict or set(row)!=base_fields|outputs:raise CaseError('report row fields')
        plain.append({k:row[k] for k in base_fields})
    validate_case_set(plain)
    for row in report['rows']:
        for side,contract in [('before','s2a'),('after','s2b')]:
            want=decision(row,contract)
            for suffix in ('expected','actual'):
                got=row[side+'_'+suffix]
                if type(got) is not dict or set(got)!=set(want) or any(type(got[k]) is not type(want[k]) for k in want):raise CaseError('Decision schema/type')
                for field in want:
                    if got[field]!=want[field]:raise CaseError(f'independent oracle {identity(row)} {side}_{suffix}.{field}: {got[field]!r} != {want[field]!r}')
            if row['c_replay']:
                c_decision=check_c(row,contract,row[side+'_c'])
                if c_decision!=want:raise CaseError('C/evaluator Decision mismatch '+str(identity(row)))
            elif row[side+'_c'] is not None:raise CaseError('unexpected C result scope')
    return len(report['rows'])

if __name__ == '__main__':
    import argparse
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--test-input',action='store_true',required=True)
    ap.parse_args()
    rows=cases()
    for row in rows:
        row['before_expected']=decision(row,'s2a');row['after_expected']=decision(row,'s2b')
    print(json.dumps(rows,separators=(',',':')))
