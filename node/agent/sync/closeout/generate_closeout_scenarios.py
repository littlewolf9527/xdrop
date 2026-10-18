#!/usr/bin/env python3
"""Deterministic closeout inputs and independent expectations; Python stdlib."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile

from adapt_historical import adapt, snapshot, verify_unchanged, historical_expectation, historical_accepts
from reference_closeout import normalized, State, identity, legal_serial

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SEED = 20261007


def packet(name='syn', src='10.10.2.1', dst='10.20.100.1', sport=1234, dport=80, ttl=64, protocol='tcp', icmp_type=0, icmp_code=0):
    p = dict(Name=name, Src=src, Dst=dst, Sport=sport, Dport=dport, Proto=6,
             Length=40, Flags=2, TTL=ttl, DSCP=0, Anomaly=0, FragClass=0,
             NonFirst=False, ICMPValid=False, ICMPType=0, ICMPCode=0)
    frag = 0
    declared, actual, doff = 40, 40, 5
    if name == 'miss':
        p['Src'] = '10.30.113.1'
    elif name == 'ack':
        p['Flags'] = 16
    elif name == 'length400':
        declared = actual = 400
    elif name == 'bad_fragment':
        # The historical frame has a complete 20-byte TCP payload: MF alone
        # does not set BAD_FRAGMENT. Recompute, never copy historical Hits.
        frag, p['FragClass'] = 0x2000, 2
    elif name == 'tiny_first':
        frag, p['FragClass'], declared, actual, p['Anomaly'] = 0x2000, 2, 28, 46, 1
    elif name == 'overflow_nonfirst':
        frag, p['FragClass'], declared, actual, p['Anomaly'], p['NonFirst'] = 8191, 1, 60, 60, 1, True
    elif name == 'normal_nonfirst':
        frag, p['FragClass'], p['NonFirst'] = 2, 1, True
    elif name == 'offset_one':
        frag, p['FragClass'], p['NonFirst'], p['Anomaly'] = 1, 1, True, 8
    elif name == 'invalid_tcp':
        doff, p['Anomaly'] = 4, 2
    elif name == 'icmp_zero':
        p.update(Proto=1, Sport=0, Dport=0, Flags=0, ICMPValid=True)
    elif name in ('length_mismatch', 'length_mismatch_ack'):
        declared, p['Anomaly'] = 60, 4
        if name.endswith('_ack'):
            p['Flags'] = 16
    elif name == 'rate':
        p['SeedEmpty'] = True
    elif name != 'syn':
        raise ValueError('unknown packet ' + name)
    if protocol != 'tcp':
        p.update(Proto={'udp': 17, 'icmp': 1, 'icmpv6': 58}[protocol], Flags=0)
        declared = actual = 28
        if protocol != 'udp':
            p.update(Sport=0, Dport=0, ICMPValid=True, ICMPType=icmp_type, ICMPCode=icmp_code)
    if p['NonFirst']:
        p.update(Sport=0, Dport=0, Flags=0)
    ipv6 = ipaddress.ip_address(p['Src']).version == 6
    if ipv6:
        assert name in ('syn', 'ack') and ipaddress.ip_address(p['Dst']).version == 6
        declared = actual = 60 if protocol == 'tcp' else 48
    p['Length'] = declared
    frame = bytearray(14+actual)
    frame[:12] = bytes.fromhex('020000000001020000000002')
    struct.pack_into('>H', frame, 12, 0x86dd if ipv6 else 0x0800)
    if ipv6:
        frame[14] = 0x60
        struct.pack_into('>H', frame, 18, actual-40)
        frame[20:22] = bytes([p['Proto'], ttl])
        frame[22:38] = ipaddress.ip_address(p['Src']).packed
        frame[38:54] = ipaddress.ip_address(p['Dst']).packed
        l4 = 54
    else:
        frame[14] = 0x45
        struct.pack_into('>H', frame, 16, declared)
        struct.pack_into('>H', frame, 20, frag)
        frame[22:24] = bytes([ttl, p['Proto']])
        frame[26:30] = ipaddress.ip_address(p['Src']).packed
        frame[30:34] = ipaddress.ip_address(p['Dst']).packed
        l4 = 34
    if p['Proto'] == 6:
        struct.pack_into('>HH', frame, l4, sport, dport)
        frame[l4+12:l4+14] = bytes([doff << 4, 16 if name.endswith('_ack') or name == 'ack' else 2])
    elif p['Proto'] == 17:
        struct.pack_into('>HHHH', frame, l4, sport, dport, actual-(40 if ipv6 else 20), 0)
    else:
        frame[l4:l4+2] = bytes([p['ICMPType'], p['ICMPCode']])
    # gate and main's Ethernet/IP guards, and L4 guards for initial TCP packets.
    assert len(frame) >= 14+(40 if ipv6 else 20)
    assert p['NonFirst'] or p['Proto'] != 6 or len(frame) >= l4+20
    p['Frame'] = frame.hex()
    p['FrameLength'] = len(frame)
    return p


def rule(id, logical_id, src='10.10.2.1', protocol='tcp', **fields):
    return dict(id=id, logical_id=logical_id, src_ip=src, protocol=protocol, action='drop', **fields)


def step(name, method, path, body=None, packets=None, **extra):
    return dict(Name=name, Method=method, Path=path, Body=body,
                Packets=copy.deepcopy(packets if packets is not None else [packet(), packet('miss')]), **extra)


def full(name, rules, packets=None, **extra):
    return step(name, 'POST', '/api/v1/sync/atomic', {'rules': rules}, packets, **extra)


def commit(name, rules, packets=None, **extra):
    groups = []
    for r in rules:
        key = identity(r)
        g = next((g for g in groups if g['key'] == key), None)
        if g is None:
            g = dict(key=key, rules=[])
            groups.append(g)
        g['rules'].append(r)
    return step(name, 'POST', '/api/v1/rules/commit', dict(groups=groups), packets, **extra)


def finish(steps):
    # Embedded S5: two drop probes and one miss guarantee unequal totals once
    # the model verifies the complete cumulative scenario below.
    steps.append(step('stats', 'GET', '/api/v1/stats', packets=[packet(), packet(), packet('miss')], Witnesses=['S5']))
    return steps


def long_scenes():
    out = []
    for index in range(3):
        logical = 1000+index*100
        r = rule('old', logical, ttl='64')
        r.update(action='rate_limit', rate_limit=1)
        reused = dict(r, id='reused')
        pure = rule('pure', logical+1, '10.11.1.1')
        second = rule('second', logical+2, '10.12.1.1')
        p = [packet(), packet(), packet()]
        rows = [full('consume-old', [r], p), full('remove-old', []),
                commit('reuse-id', [reused], p), commit('identical-commit', [reused]),
                step('empty-members', 'POST', '/api/v1/rules/commit', {'groups': [dict(key=identity(reused), rules=[])]}),
                step('single-add', 'POST', '/api/v1/rules', pure),
                step('single-update', 'PUT', '/api/v1/rules/pure', dict(pure, action='rate_limit', rate_limit=1)),
                step('single-delete', 'DELETE', '/api/v1/rules/pure'),
                step('batch-duplicate', 'POST', '/api/v1/rules/batch', {'rules': [pure, pure]}),
                step('batch-partial', 'POST', '/api/v1/rules/batch', {'rules': [second, dict(pure, logical_id=0, id='invalid')]}),
                step('batch-delete', 'DELETE', '/api/v1/rules/batch', {'ids': ['pure', 'second', 'absent']}),
                full('replace', [rule('background', logical+3)]),
                step('whitelist-add', 'POST', '/api/v1/whitelist', {'id': 'wl', 'src_ip': '10.10.2.1'}),
                step('whitelist-list', 'GET', '/api/v1/whitelist'),
                step('whitelist-delete', 'DELETE', '/api/v1/whitelist/wl'),
                full('clear-again', []), commit('new-group', [dict(r, id='fresh', logical_id=logical+4)], p),
                commit('unchanged-again', [dict(r, id='fresh', logical_id=logical+4)]),
                full('final-background', [rule('background', logical+3)]),
                step('health', 'GET', '/api/v1/health')]
        out.append(dict(Family='S1', Name='S1/long-'+str(index), TrackB=True, Steps=finish(rows)))
    rows = copy.deepcopy(out[0]['Steps'][:-1])
    cidr_rule = rule('cidr', 1900)
    cidr_rule.pop('src_ip')
    cidr_rule['src_cidr'] = '10.10.2.0/24'
    rows += [full('cidr-seed', [cidr_rule]), step('cidr-withdraw', 'DELETE', '/api/v1/rules/cidr', Fault='trie_delete'),
             full('withdrawal-paid', [rule('background', 1901)])]
    out.append(dict(Family='S1', Name='S1/withdrawal', TrackB=False, Steps=finish(rows)))
    assert all(20 <= len(s['Steps']) <= 60 for s in out)
    return out


def prefix_apply_scenes():
    # PLAN TD-096 §三-2: separate fixtures preserve all historical scene bytes.
    out = []
    for index in range(1, 13):
        side = 'dst_cidr' if index in (3, 9) else 'src_cidr'
        pnet = '10.96.1.0/24' if index in (2, 9) else 'fd00:96:1::/64'
        qside = 'dst_cidr' if index == 3 else 'src_cidr'
        qnet = 'fd00:96:2::/64' if index in (2, 9) else '10.96.2.0/24'
        p = dict(id=f'td096-x{index}-p', logical_id=96000+index*10+1, protocol='tcp', action='drop', **{side: pnet})
        q = dict(id=f'td096-x{index}-q', logical_id=96000+index*10+2, protocol='tcp', action='drop', **{qside: qnet})
        rows = [(full if index == 4 else commit)('seed-p', [p], [])]
        if index in (10, 11, 12):
            if index == 10: rows[0]['Fault'] = 'capacity_one'
            rows.append(full('replace-q', [q], [], Fault='full_step1_delete' if index == 11 else 'trie_delete'))
            if index == 12:
                r = dict(id='td096-x12-r', logical_id=96123, src_cidr='10.96.3.0/24', protocol='tcp', action='drop')
                rows.append(commit('c3-r', [r], [], Fault='c-3'))
        elif index in (5, 6, 8):
            swap = dict(groups=[dict(key=identity(p), rules=[]), dict(key=identity(q), rules=[q])])
            rows.append(step('swap-q', 'POST', '/api/v1/rules/commit', swap, [], Fault={5: 'trie_delete', 6: 'c-7', 8: 'Rc'}[index]))
            rows.append(step('retry-swap', 'POST', '/api/v1/rules/commit', copy.deepcopy(swap), []) if index == 5
                        else full('retry-p', [p], [], Fault='trie_delete'))
        else:
            rows.append(full('replace-q', [q], [], Fault='trie_delete'))
            if index == 7:
                r = dict(id='td096-x7-r', logical_id=96073, src_cidr='10.96.3.0/24', protocol='tcp', action='drop')
                rows.append(commit('catchup-r', [r], [], Fault='trie_delete'))
            elif index != 4:
                rows.append(full('retry-p', [p], [], Fault='trie_delete'))
        rows += [step(f'observe-{i:02d}', 'GET', '/api/v1/health', packets=[]) for i in range(len(rows), 20)]
        out.append(dict(Family='S1', Name=f'S1/TD096-X{index}', TrackB=False, Steps=rows))
    assert all(20 <= len(s['Steps']) <= 60 for s in out)
    return out


def grid_scenes():
    addresses = [('10.41.1.7', '10.51.1.9'), ('10.42.1.8', '10.52.1.10'), ('10.43.1.9', '10.53.1.11'),
                 ('fd00:41::7', 'fd00:51::9'), ('fd00:42::8', 'fd00:52::a')]
    probes = [packet(src=a, dst=b, sport=2000+i, dport=3000+i) for i, (a, b) in enumerate(addresses)]
    exact = [rule('grid-'+str(i), 2000+i, a, dst_ip=b, src_port=2000+i, dst_port=3000+i) for i, (a, b) in enumerate(addresses)]
    networks = []
    for r in exact:
        n = dict(r, id=r['id']+'-cidr', logical_id=r['logical_id']+10)
        for side in ('src', 'dst'):
            addr = n.pop(side+'_ip')
            n[side+'_cidr'] = str(ipaddress.ip_network(addr+('/64' if ':' in addr else '/24'), strict=False))
        networks.append(n)
    rows = [full('exact-full', exact, probes), full('clear', [], probes), commit('exact-commit', exact, probes),
            full('cidr-full', networks, probes), full('clear-cidr', [], probes), commit('cidr-commit', networks, probes),
            full('stats-background', [rule('background', 2099)])]
    out = [dict(Family='S2', Name='S2/grid', Steps=finish(rows))]
    for missing in ('src', 'dst'):
        a = dict(id='alias-a', logical_id=2111, dst_cidr='10.20.100.0/24', src_port=12345, protocol='tcp', action='drop')
        b = dict(id='native-b', logical_id=2112, dst_cidr='10.20.100.0/24', dst_port=443, protocol='tcp', action='rate_limit', rate_limit=1)
        c = dict(id='enabler', logical_id=2113, src_cidr='10.30.113.0/24', dst_cidr='10.20.100.0/24', src_port=12345, protocol='tcp', action='drop')
        if missing == 'dst':
            for r in (a, b):
                r.pop('dst_cidr')
                r['src_cidr'] = '10.10.2.0/24'
            c['src_cidr'], c['dst_cidr'] = '10.10.2.0/24', '10.30.113.0/24'
        probes = [packet(sport=12345, dport=443)]*3
        rows = [commit('zero-prefix-id-alias', [a, b, c], probes), full('stats-background', [rule('background', 2199)], [packet(), packet()])]
        out.append(dict(Family='S2', Name='S2/TD084-'+missing, NoRefillNS=1000000000, Steps=finish(rows)))
    for family in ('udp', 'icmp'):
        for v6 in (False, True):
            src, dst = ('fd00:44::7', 'fd00:54::9') if v6 else ('10.44.1.7', '10.54.1.9')
            proto = 'icmpv6' if family == 'icmp' and v6 else family
            kwargs = dict(src=src, dst=dst, protocol=proto)
            fields = dict(src_port=1234, dst_port=80) if family == 'udp' else dict(icmp_type=str(128 if v6 else 8), icmp_code='0')
            probes = [packet(**kwargs, **({} if family == 'udp' else {k: int(v) for k,v in fields.items()})),
                      packet(**kwargs, **(dict(dport=81) if family == 'udp' else dict(icmp_type=int(fields['icmp_type'])+1, icmp_code=0))),
                      packet(**kwargs, **(dict(sport=1235) if family == 'udp' else dict(icmp_type=int(fields['icmp_type']), icmp_code=1)))]
            exact = rule(family+'-exact', 2200+100*int(v6)+10*int(family == 'icmp'), src, protocol=proto, dst_ip=dst, **fields)
            network = dict(exact, id=family+'-cidr', logical_id=exact['logical_id']+1)
            for side in ('src', 'dst'):
                address = network.pop(side+'_ip')
                network[side+'_cidr'] = str(ipaddress.ip_network(address+('/64' if v6 else '/24'), strict=False))
            rows = [full('exact-full', [exact], probes), full('clear-exact', [], []), commit('exact-commit', [exact], probes),
                    full('cidr-full', [network], probes), full('clear-cidr', [], []), commit('cidr-commit', [network], probes)]
            out.append(dict(Family='S2', Name='S2/'+family+('-v6' if v6 else '-v4'), Steps=rows))
    return out


def rate_scenes():
    a = rule('anomaly', 3001, match_anomaly=4)
    b = rule('ttl', 3002, ttl='63')
    a.update(action='rate_limit', rate_limit=1)
    b.update(action='rate_limit', rate_limit=2)
    probes = [packet('length_mismatch')]*3 + [packet(ttl=63)]*5
    rows = [commit('two-candidates', [a, b], probes), full('stats-background', [rule('background', 3099)])]
    return [dict(Family='S3', Name='S3/independent-buckets', NoRefillNS=500000000, Steps=finish(rows))]


def whitelist_scenes():
    out = []
    fields = [('src_ip', '10.10.2.1'), ('dst_ip', '10.20.100.1'), ('src_port', 1234), ('dst_port', 80), ('protocol', 'tcp')]
    for mask in range(1, 32):
        wl = dict(id='wl-'+str(mask), **{k: v for bit, (k, v) in enumerate(fields) if mask & (1 << bit)})
        rows = [full('background', [rule('drop', 4000+mask)], [packet()]),
                step('single-whitelist', 'POST', '/api/v1/whitelist', wl, [packet()]),
                step('single-delete', 'DELETE', '/api/v1/whitelist/'+wl['id'])]
        out.append(dict(Family='S4', Name='S4/combo-'+str(mask), ComboMask=mask, Steps=finish(rows)))
    wl = {'id': 'wl', 'src_ip': '10.10.2.1'}
    conditional = rule('limited', 4090, ttl='64')
    conditional.update(action='rate_limit', rate_limit=1)
    rows = [commit('condition-drop', [rule('drop', 4091, ttl='64')]),
            step('batch-add', 'POST', '/api/v1/whitelist/batch', {'entries': [wl]}),
            step('list', 'GET', '/api/v1/whitelist'), full('condition-rate-full', [conditional], [packet()]*3),
            step('batch-delete', 'DELETE', '/api/v1/whitelist/batch', {'ids': ['wl', 'absent']}),
            step('full-whitelist', 'POST', '/api/v1/sync/whitelist', {'entries': [wl]}),
            commit('condition-rate-commit', [dict(conditional, id='committed')], [packet()]*3),
            step('full-clear', 'POST', '/api/v1/sync/whitelist', {'entries': []}),
            full('stats-background', [rule('background', 4099)])]
    out.append(dict(Family='S4', Name='S4/lifecycle', Steps=finish(rows)))
    return out


def fragment_scenes():
    r = rule('fragment-rate', 6001, match_anomaly=1)
    r.update(action='rate_limit', rate_limit=1)
    probes = [packet('overflow_nonfirst')]*3 + [packet('normal_nonfirst')]
    return [dict(Family='S6', Name='S6/reassembly-overflow', NoRefillNS=1000000000,
                 Steps=[full('overflow-exhaust', [r], probes), full('reset-tiny', [r], []),
                        step('tiny-first-control', 'GET', '/api/v1/health', packets=[packet('tiny_first')]),
                        step('stats', 'GET', '/api/v1/stats', packets=[packet('normal_nonfirst')])])]


def concurrency():
    single = [commit('a'+str(i), [rule('a'+str(i), 7000+i, '10.71.1.'+str(i))], []) for i in (1, 2)]
    commits = [commit('c'+str(i), [rule('c'+str(i), 7100+i, '10.72.1.'+str(i), ttl='64')], []) for i in (1, 2)]
    replace = full('replace', [rule('full', 7201, '10.73.1.1')], [])
    wl = step('whitelist', 'POST', '/api/v1/sync/whitelist', {'entries': [{'id': 'concurrent-wl', 'src_ip': '10.74.1.1'}]}, [])
    legal = legal_serial(single, commits, replace, wl)
    for item in legal:
        ids = {r['id'] for r in item['terminal']['installed']['rules']}
        assert 'a1' not in ids and 'c1' not in ids
    print(f'CLOSEOUT_S7_PROOF pairs={len(legal)} serializations={sum(len(r["replies"]) for r in legal)} commuting=1 barrier_cleared=2')
    return dict(Single=single, Commits=commits, Full=replace, Whitelist=wl, Legal=legal,
                Packets=[packet(src='10.73.1.1'), packet('miss')])


def characterizations():
    def cell(leaf, td, track, method, path, body, expected, evidence):
        return dict(Leaf=leaf, TD=td, Track=track, Method=method, Path=path, Body=body,
                    Expected=expected, Registration='registered', Evidence=evidence)
    out = [cell('TD020-health', 'TD-020', 'B', 'GET', '/api/v1/health', None,
                dict(initial=dict(status='degraded', reason='awaiting_full_sync', rules_synced=False, whitelist_synced=False), after=dict(status='healthy')),
                ['api/handlers.go:Health', 'api/sync.go:AtomicSync', 'api/sync.go:SyncWhitelistHandler']),
           cell('startup-empty', 'TD-086', 'B', 'GET', '/api/v1/rules', None, {'rules': 0, 'whitelist': 0},
                ['main.go:PreparePinnedStartup before gin.Default; no reverse pull'])]
    bad = dict(id='reversed-cidr', logical_id=9064, src_cidr='10.64.1.0/24', protocol='tcp', action='drop', pkt_len_min=200, pkt_len_max=100)
    entries = [('atomic', '/api/v1/sync/atomic', {'rules': [bad]}, 409, 'condition_group_invalid'),
               ('commit', '/api/v1/rules/commit', {'groups': [dict(key=identity(bad), rules=[bad])]}, 400, 'validation_rejected')]
    for entry, path, body, status, code in entries:
        out.append(cell('TD064-'+entry, 'TD-064', 'A', 'POST', path, body,
                        dict(http=status, code=code, installed=False),
                        ['api/condition_atomic.go:prepareAtomicRule',
                         'api/commit_preflight.go:preflightCommit', 'condexpr/compile.go:Compile']))
    mapped = dict(id='mapped-cidr', logical_id=9076, src_cidr='::ffff:10.76.1.0/120', protocol='tcp', action='drop')
    for entry, path, body, code in [('atomic', '/api/v1/sync/atomic', {'rules': [mapped]}, None),
                                    ('commit', '/api/v1/rules/commit', {'groups': [dict(key=identity(normalized(mapped)), rules=[mapped])]}, 'committed')]:
        out.append(cell('TD076-'+entry, 'TD-076', 'A', 'POST', path, body,
                        dict(http=200 if entry == "atomic" else 400, code=None if entry == "atomic" else "validation_rejected", published=False, prefix_len=None),
                        ['api/convert.go:checkAddressFamily', 'api/condition_groups.go:classifyRuleKey',
                         'api/condition_atomic.go:prepareAtomicRule']))
    assert len(out) == 6 and len({c['Leaf'] for c in out}) == 6
    return out


def deleted_routes():
    rows = [('POST', '/api/v1/rules'), ('PUT', '/api/v1/rules/deleted'),
            ('DELETE', '/api/v1/rules/deleted'), ('POST', '/api/v1/rules/batch'),
            ('DELETE', '/api/v1/rules/batch'), ('POST', '/api/v1/whitelist'),
            ('DELETE', '/api/v1/whitelist/deleted'), ('POST', '/api/v1/whitelist/batch'),
            ('DELETE', '/api/v1/whitelist/batch')]
    steps = [full('seed', [rule('retained', 9100)])]
    steps += [step('removed-'+str(i), method, path, {}, [packet()]) for i, (method, path) in enumerate(rows)]
    return [dict(Family='S9', Name='S9/deleted-routes', TrackB=True, Steps=steps)]


def build():
    random.seed(SEED)
    before = snapshot()
    scenes = long_scenes()+grid_scenes()+rate_scenes()+whitelist_scenes()+fragment_scenes()
    history, old_expect, history_counts = adapt(packet)
    scenes += history
    from translate_p7 import translate_scenes
    migration = translate_scenes(scenes)
    scenes += deleted_routes()+prefix_apply_scenes()
    data = dict(Seed=SEED, Scenes=scenes, Migration=migration, Concurrent=concurrency(), HistoricalCounts=history_counts,
                Characterizations=characterizations(), Judgments=[dict(Leaf='TD039-window', Body=dict(parent='10.90.0.0/16', child='10.90.1.0/24', probe=packet(src='10.90.1.7')), Expected=dict(written_copy='shadow', verdict=1)), dict(Leaf='TD039-reverse', Expected=dict(old_copy_has_old=1))])
    verify_unchanged(before)
    return data, old_expect


def track_b_inputs():
    rules = [rule('startup-plain', 8301, '10.83.1.1'),
             dict(id='startup-cidr', logical_id=8302, src_cidr='10.83.2.0/24', protocol='tcp', action='drop'),
             dict(rule('startup-rate', 8303, '10.83.3.1', match_anomaly=4), action='rate_limit', rate_limit=1),
             dict(rule('startup-disabled', 8304, '10.83.4.1'), enabled=False)]
    wl = [dict(id='startup-wl', src_ip='10.83.5.1')]
    probes = [packet(src='10.83.1.1'), packet(src='10.83.6.1'), packet(src='10.83.5.1')]
    probes += [packet('length_mismatch', src='10.83.3.1')]*3
    return dict(rules=rules, entries=wl, packets=probes, bucket_id=8303, no_refill_ns=1000000000)


def track_b_state(fixture, include_disabled=False):
    state = State()
    state.request(step('wl', 'POST', '/api/v1/sync/whitelist', {'entries': fixture['entries']}, []))
    rules = [{k: v for k, v in r.items() if k != 'enabled'} for r in fixture['rules']
             if include_disabled or r.get('enabled', True)]
    state.request(full('rules', rules, []))
    return state


def counts(data):
    out = {}
    for scene in data['Scenes']:
        row = out.setdefault(scene['Family'], [0, 0, 0])
        row[0] += 1
        row[1] += len(scene['Steps'])
        row[2] += sum(len(s['Packets']) for s in scene['Steps'])
        embedded = [s for s in scene['Steps'] if 'S5' in s.get('Witnesses', [])]
        if embedded:
            stat = out.setdefault('S5', [0, 0, 0])
            stat[0] += 1
            stat[1] += len(embedded)
            stat[2] += sum(len(s['Packets']) for s in embedded)
    out['S7'] = [1, 6, len(data['Concurrent']['Packets'])]
    assert out['S8'] == [160, 354, 633]
    for family in sorted(out):
        assert all(n > 0 for n in out[family]), (family, out[family])
        print('CLOSEOUT_FAMILY family=%s scenes=%d steps=%d packets=%d' % (family, *out[family]))
    requests = sum(len(s.get('Requests', [s])) for scene in data['Scenes'] if scene['Family'] == 'S8' for s in scene['Steps'])
    print('CLOSEOUT_S8_SCALE scenes=%d steps=%d packets=%d requests=%d' % (*out['S8'], requests))
    rules = []
    def visit(value):
        if isinstance(value, dict):
            if 'logical_id' in value and 'protocol' in value: rules.append(value)
            for v in value.values(): visit(v)
        elif isinstance(value, list):
            for v in value: visit(v)
    visit([s['Steps'] for s in data['Scenes']])
    packets = [p for scene in data['Scenes'] for step in scene['Steps'] for p in step['Packets']]
    values = [sum(r['protocol'] == 'udp' for r in rules), sum(p['Proto'] == 17 for p in packets),
              sum(r['protocol'] in ('icmp','icmpv6') for r in rules), sum(p['Proto'] in (1,58) for p in packets)]
    assert values[0] >= 1 and values[1] >= 1 and values[2] > 2 and values[3] > 4, values
    print('CLOSEOUT_PROTO udp_rules=%d udp_packets=%d icmp_rules=%d icmp_packets=%d' % tuple(values))
    return out


def generate(output, artifact_dir):
    data, old = build()
    data['Counts'] = counts(data)
    env_intent = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local',
                      XDROP_CLOSEOUT_INTENTS_OUT=str(output.parent/'intents.json'))
    subprocess.run(['go', 'test', '-run', '^TestAPIFinalIntentSources$', '-count=1', '-v', './api'],
                   cwd=ROOT/'node/agent', env=env_intent, check=True)
    intents_path = output.parent/'intents.json'
    intents_raw = intents_path.read_bytes()
    intents = json.loads(intents_raw)
    assert (json.dumps(intents, indent=2, ensure_ascii=False)+'\n').encode() == intents_raw
    # Go map iteration order is unspecified; Absent represents a set.
    for intent in intents.values():
        intent['Absent'].sort()
    intents_path.write_bytes((json.dumps(intents, indent=2, ensure_ascii=False)+'\n').encode())
    inputs = {}
    for scene in data['Scenes']:
        inputs.update(State().run_closeout(scene)[1])
    for candidate in data['Concurrent']['Legal']:
        key = 'S7/%d/%d' % (candidate['i'], candidate['j'])
        terminal = candidate['terminal']
        inputs[key] = dict(Rules=terminal['installed']['rules'],
                           Whitelist=[dict(r, logical_id=0x70000000+i, action='drop') for i, r in enumerate(terminal['whitelist']['entries'])],
                           Packets=data['Concurrent']['Packets'])
    fixture = track_b_inputs()
    bs = track_b_state(fixture)
    inputs['B-6'] = dict(Rules=bs.installed, Whitelist=[dict(r, logical_id=0x70000000+i, action='drop')
                         for i, r in enumerate(bs.whitelist)], Packets=fixture['packets'])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    oracle_in, oracle_out = artifact_dir/'oracle-input.json', artifact_dir/'oracle.json'
    oracle_in.write_text(json.dumps(inputs, indent=2)+'\n')
    env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local',
               XDROP_CLOSEOUT_ORACLE_INPUT=str(oracle_in), XDROP_CLOSEOUT_ORACLE_OUT=str(oracle_out))
    subprocess.run(['go', 'test', '-run', '^TestCloseoutOracle$', '-count=1', '-v', '.'], cwd=ROOT/'node/agent', env=env, check=True)
    oracle = json.loads(oracle_out.read_text())
    s7_predictions = []
    for candidate in data['Concurrent']['Legal']:
        state = State()
        terminal = candidate['terminal']
        state.full([{k: v for k, v in r.items() if k != 'stats'} for r in terminal['installed']['rules']])
        key = 'S7/%d/%d' % (candidate['i'], candidate['j'])
        s7_predictions.append([state.project_packet(p, w) for p, w in zip(data['Concurrent']['Packets'], oracle[key])])
    assert all(rows == s7_predictions[0] for rows in s7_predictions)
    data['Concurrent']['ExpectedPackets'] = s7_predictions[0]
    b_expected = dict(installed=bs.installed_response(), whitelist=bs.whitelist_response(),
                      rules_count=len(bs.installed), bucket_after_restart={'present': False},
                      xdp_info=dict(mode='traditional', interfaces=[dict(name='closeout0', role='filter', attach_mode='generic')]))
    before = bs.stats_response()
    for p, w in zip(fixture['packets'], oracle['B-6']):
        bs.project_packet(p, w)
    b_expected['delta'] = {k: bs.stats_response()[k]-before[k] for k in ('total_packets', 'passed_packets',
                            'dropped_packets', 'whitelisted_packets', 'rate_limited_packets')}
    (artifact_dir/'track-b-fixture.json').write_text(json.dumps(fixture, indent=2)+'\n')
    (artifact_dir/'track-b-expected.json').write_text(json.dumps(b_expected, indent=2)+'\n')
    expected, migration = {}, list(data['Migration'])
    for scene in data['Scenes']:
        records, _ = State().run_closeout(scene, oracle)
        expected.update(records)
        for s in scene['Steps']:
            case = scene['Name']+'/'+s['Name']
            s['RateLimits'] = {str(r['logical_id']): r['rate_limit'] for r in inputs[case]['Rules'] if r['action'] == 'rate_limit'}
            if 'S5' in s.get('Witnesses', []):
                stats = records[case]['stats']
                assert stats['dropped_packets'] != stats['passed_packets'], ('S5 unequal counters', case)
            s['Hits'] = [bool(v['RuleID']) for v in oracle[case]]
            if case in old:
                protocol, field, prior = historical_expectation(scene['Source'], old[case])
                body = records[case]['body']
                if prior and not historical_accepts(prior, records[case]['status'], body):
                    migration.append(dict(case=case, historical_protocol=protocol, historical_field=field, historical=old[case],
                                          reason='§3 A2/Q-W/Q-A8/A9/A10: protocol 8 response/state contract', protocol8=dict(status=records[case]['status'], body=body)))
    output.write_text(json.dumps(data, indent=2)+'\n')
    (artifact_dir/'expected.json').write_text(json.dumps(expected, indent=2)+'\n')
    (artifact_dir/'migration.json').write_text(json.dumps(migration, indent=2)+'\n')
    print(f'CLOSEOUT_GENERATED scenes={len(data["Scenes"])} records={len(expected)} migration={len(migration)} observations=0')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, default=HERE/'scenarios_closeout.json')
    p.add_argument('--artifacts', type=Path, required=True)
    args = p.parse_args()
    generate(args.output, args.artifacts.resolve())
