#!/usr/bin/env python3
"""Protocol 5/6 finite J8 extension, with frozen p2-p5 sources untouched.

Historical inputs delegate unchanged to p5. The previously unmodelled J8
rejections are specified here against the baseline node, before projecting the
protocol-6 removal. Winners come only from the post-cut54 B1 evaluator on both
sides, never observed ELF records or the legacy anomaly-stage evaluator.
"""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
from compare import differences, validate_cut56_authority
from reference_p3 import response_projection
from reference_p4 import identity, LE32
from reference_p5 import State as P5State

DROP_ONLY = 'anomaly rules are drop-only (match_anomaly != 0 requires action=drop)'
BOUNDED = 'anomaly rule requires a bounded target (src/dst IP must not be empty/wildcard, CIDR must not be /0)'
IPV6 = 'bad_fragment not supported for IPv6 target'

class State(P5State):
    def anomaly_error(self, r):
        # Domain extension only: old valid inputs and old model files are frozen.
        bits = r.get('match_anomaly', 0)
        if not bits or r.get('action') != 'rate_limit': return None
        if r.get('rate_limit', 0) <= 0: return 'rate_limit must be > 0 for rate_limit action'
        if bits & ~15: return 'invalid match_anomaly bits: 0x%x (valid: 0xf)' % bits
        if self.protocol < 6: return DROP_ONLY
        addresses = [ipaddress.ip_address(r[k]) for k in ('src_ip', 'dst_ip') if r.get(k)]
        prefixes = [ipaddress.ip_network(r[k], strict=False) for k in ('src_cidr', 'dst_cidr') if r.get(k)]
        if not any(not ip.is_unspecified for ip in addresses) and not any(n.prefixlen > 0 for n in prefixes): return BOUNDED
        if bits & 9 and any(a.version == 6 for a in addresses + prefixes):
            return IPV6 if bits & 1 else 'match_anomaly 0x08 not supported for IPv6 target'
        return None

    def full(self, rules, fault=''):
        for group in self.grouped(rules):
            reasons = [self.anomaly_error(r) for r in group]
            if any(reasons):
                reason = next(r for r in reasons if r)
                return self.reject('condition_group_invalid', 'condition group invalid; batch not published',
                                   key=identity(group[0]), conflicts=[dict(id=r['id'], reason=e or reason) for r, e in zip(group, reasons)], added=0, failed=1)
        return super().full(rules, fault)

    def commit(self, groups, fault=''):
        for index, group in enumerate(groups):
            for rule in group['rules']:
                reason = self.anomaly_error(rule)
                if reason:
                    return 400, dict(code='validation_rejected', error=reason,
                                     groups=[dict(index=index, code='validation_rejected', error=reason)], withdrawal_pending=False)
        return super().commit(groups, fault)

    def take(self, r):
        if not (self.protocol >= 6 and r.get('match_anomaly')):
            return super().take(r)
        # J8 cold-bucket witnesses run inside the no-refill window. Resolve the
        # same configured divisor/fallback as TD-074, preserving old test vectors.
        divisor = int.from_bytes(bytes.fromhex(self.maps[('config_a', 'config_b')[self.config_slot]][LE32(11)]), 'little')
        divisor = min(divisor or 256, 4096)
        rate = r['rate_limit']; capacity = (2 * rate + divisor - 1) // divisor
        n, k = self.bucket(r); cpu = self.packet_cpu
        if k not in self.maps[n]:
            self.maps[n][k] = dict(tokens=[0]*self.cpus, last_update_present=[False]*self.cpus)
            self.times[n, k] = [0]*self.cpus
        row, stamps = self.maps[n][k], self.times[n, k]
        last = stamps[cpu]
        if last == 0: tokens, last, allowed = capacity-1, self.now, True
        else:
            last = min(last, self.now)
            elapsed = min(self.now-last, (capacity*divisor*1_000_000_000+rate-1)//rate)
            added = elapsed*rate//(divisor*1_000_000_000)
            tokens = min(capacity, min(row['tokens'][cpu], capacity)+added)
            if tokens == capacity: last = self.now
            elif added: last += (added*divisor*1_000_000_000+rate-1)//rate
            allowed = tokens >= 1; tokens -= int(allowed)
        row['tokens'][cpu], stamps[cpu] = tokens, last
        row['last_update_present'] = [bool(x) for x in stamps]
        return allowed

    def run(self, scene, oracle=None):
        # Reuse the frozen runner, selecting the requested protocol's independent
        # winner list through its existing P4 slot (both APIs use logical IDs).
        projected = None
        if oracle is not None:
            version = 'P6' if self.protocol >= 6 else 'P5'
            projected = {case: {'P4': decisions[version]} for case, decisions in oracle.items()}
        return super().run(scene, projected)

def inputs(scenes):
    out = {}
    for scene in scenes:
        old = State(5).run(scene)[1]; new = State(6).run(scene)[1]
        for step in scene['Steps']:
            case = scene['Name']+'/'+step['Name']
            out[case] = dict(RulesP5=old[case], RulesP6=new[case], Packets=step['Packets'])
    return out

def records_and_table(scenes, oracle, cpus=1, cpu=0):
    old, new, table = {}, {}, []
    for scene in scenes:
        a = State(5, cpus, cpu).run(scene, oracle)[0]
        b = State(6, cpus, cpu).run(scene, oracle)[0]
        old.update(a); new.update(b)
        for path, x, y in differences(a, b):
            if path == ('I9_protocol/welcome', 'body', 'sync_protocol'):
                if (x,y)!=(5,6): raise AssertionError('I9 must be 5 -> 6')
                token = 'I9'
            elif scene['Name'].startswith(('J8_accept_rate_', 'J8_rejected_')):
                token = 'J8'
            else:
                raise AssertionError('unapproved model divergence: '+str(path))
            row = dict(case=path[0], field=list(path[1:]), old=x, new=y, authority=token+' PLAN ④-1 / authorization 4')
            validate_cut56_authority(row, a, b); table.append(row)
    return old, new, table

def main():
    p=argparse.ArgumentParser();p.add_argument('--scenarios',type=Path,required=True)
    p.add_argument('--oracle-input',type=Path);p.add_argument('--oracle',type=Path)
    p.add_argument('--possible-cpus',type=int,default=1);p.add_argument('--packet-cpu',type=int,default=0)
    p.add_argument('--output',type=Path);p.add_argument('--expected',type=Path);p.add_argument('--baseline-expected',type=Path);p.add_argument('--prepared-scenarios',type=Path)
    a=p.parse_args();scenes=json.loads(a.scenarios.read_text())
    if a.oracle_input:
        v=inputs(scenes);a.oracle_input.write_text(json.dumps(v,indent=2)+'\n')
        print('CUT56_ORACLE_INPUT cases=%d observations=0'%len(v));return
    oracle=json.loads(a.oracle.read_text());old,new,table=records_and_table(scenes,oracle,a.possible_cpus,a.packet_cpu)
    for scene in scenes:
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name']
            step['HitsP4']=[bool(x['RuleID']) for x in oracle[case]['P5']]
            step['HitsP6']=[bool(x['RuleID']) for x in oracle[case]['P6']]
    for path,value in ((a.output,table),(a.expected,new),(a.baseline_expected,old),(a.prepared_scenarios,scenes)):
        if path:path.write_text(json.dumps(value,indent=2)+'\n')
    from collections import Counter
    print('CUT56_MODEL records=%d allowed=%s observations=0'%(len(new),dict(Counter(r['authority'].split()[0] for r in table))))
if __name__=='__main__':main()
