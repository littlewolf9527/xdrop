#!/usr/bin/env python3
"""Protocol-6/7/8/9/10/11 specification. No observed node output is an input."""
import copy
import ipaddress
import itertools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'cut5a_replay'))
from reference_p6 import State as P6State
from reference_p5 import State as P5State
from reference_p3 import canonical, extended
from reference_p4 import LE32, LE64, cidr, groupkey, identity, combo
from compare_closeout import COUNTERS


def normalized(rule):
    out = canonical(rule)
    out.setdefault('action', 'drop')
    out.setdefault('protocol', 'all')
    for field in ('src_cidr', 'dst_cidr'):
        if out.get(field):
            net = ipaddress.ip_network(out[field], strict=False)
            if net.version == 6 and net.network_address.ipv4_mapped and net.prefixlen >= 96:
                net = ipaddress.ip_network(f'{net.network_address.ipv4_mapped}/{net.prefixlen - 96}')
            out[field] = str(net)
    for field in ('src_ip', 'dst_ip'):
        if out.get(field):
            addr = ipaddress.ip_address(out[field])
            if addr.is_unspecified:
                out.pop(field)
            else:
                out[field] = str(addr.ipv4_mapped or addr) if addr.version == 6 else str(addr)
    return out


class State(P6State):
    def __init__(self, protocol=11, cpus=1, packet_cpu=0):
        assert protocol in (6, 7, 8, 9, 10, 11)
        super().__init__(protocol, cpus, packet_cpu)
        self.rules_synced = self.whitelist_synced = False
        self.whitelist = []
        self.maps['stats'][LE32(5)] = [0]
        self.wl_slot = 0
        self.withdrawal = False
        self.prefix_copies = [set(), set()]
        self.prefix_known = [False, False]
        for name in ('config_a', 'config_b'):
            self.maps[name][LE32(11)] = LE64(1)

    def family_reason(self, rule, prepared=False):
        if self.protocol < 9: return None
        prefix = bool(rule.get('src_cidr') or rule.get('dst_cidr'))
        parsed = []
        try:
            for side in ('src', 'dst'):
                field = side + ('_cidr' if prefix else '_ip')
                raw = rule.get(field, '')
                if not raw or (not prefix and raw in ('0.0.0.0', '::')):
                    continue
                address, mask = raw.rsplit('/', 1) if prefix else (raw, None)
                ip = ipaddress.ip_address(address)
                bits = int(mask) if prefix else None
                if prefix and not 0 <= bits <= ip.max_prefixlen:
                    return None
                parsed.append((field, raw, ip, bits))
        except ValueError:
            return None
        def preceding(reason):
            if not prepared or (prefix and reason and rule.get('rate_limit', 0) > 0): return reason
            target = dict(rule)
            if not prefix:
                for field, _, ip, _ in parsed:
                    target[field] = str(getattr(ip, 'ipv4_mapped', None) or ip)
                for field in ('src_ip', 'dst_ip'):
                    if target.get(field) and ipaddress.ip_address(target[field]).is_unspecified:
                        target.pop(field)
            return self.anomaly_error(target) or reason
        families = []
        for field, raw, ip, bits in parsed:
            if ip.version == 6 and ip.ipv4_mapped is not None:
                kind, suggestion = 'address', '; write the IPv4 address ' + str(ip.ipv4_mapped)
                if prefix:
                    kind, suggestion = 'prefix', ''
                    if bits >= 96:
                        suggestion = '; write the IPv4 prefix ' + str(ipaddress.ip_network(str(ip.ipv4_mapped)+'/'+str(bits-96), strict=False))
                return preceding(f'invalid {field}: IPv4-mapped IPv6 {kind} {raw}{suggestion}')
            families.append(ip.version)
        if len(families) == 2 and families[0] != families[1]:
            return preceding(f'address family mismatch: src is IPv{families[0]}, dst is IPv{families[1]}')
        return preceding(None)

    def installed_response(self):
        rules = []
        for source in self.installed:
            rule = normalized(source)
            rule.pop('comment', None)
            match, drop = self.maps['id_counts'].get(LE32(rule.get('logical_id', 0)), [0, 0])
            rule['stats'] = {'match_count': match, 'drop_count': drop, 'drop_pps': 0.0}
            rules.append(rule)
        out = {'count': len(rules), 'rules': sorted(rules, key=lambda r: r['id'])}
        if self.protocol >= 7:
            out['pagination'] = dict(page=1, limit=50, total=len(rules), pages=(len(rules)+49)//50)
            out['rules'] = out['rules'][:50]
        return out

    def whitelist_response(self):
        rows = []
        for source in self.whitelist:
            rule = {k: v for k, v in source.items() if k not in ('comment', 'action', 'logical_id') and v not in ('', 0, None)}
            rule.setdefault('protocol', 'all')
            rows.append(rule)
        return {'count': len(rows), 'entries': sorted(rows, key=lambda r: r['id'])}

    def stats_response(self):
        out = {key: self.maps['stats'][LE32(i)][0] for i, key in enumerate(COUNTERS)}
        out.update(mapped_v6_dropped=self.maps['stats'][LE32(5)][0], cond_row_missing=0, tailcall_fail=0, rules_count=len(self.installed), whitelist_count=len(self.whitelist),
                   dropped_pps=0.0, passed_pps=0.0, total_pps=0.0, system={},
                   agent_state=dict(exact_rules=sum(not cidr(r) for r in self.installed), cidr_rules=sum(cidr(r) for r in self.installed),
                                    whitelist_entries=len(self.whitelist), active_slot=self.config_slot, rule_map_selector=self.slot))
        return out

    def project_packet(self, packet, winner):
        # Every probe enters gate; whitelist exits before main's logical counters.
        self.maps['stats'][LE32(0)][0] += 1
        if winner['Stage'] == 'whitelist':
            self.maps['stats'][LE32(2)][0] += 1
            self.maps['stats'][LE32(3)][0] += 1
            return {'packet': packet['Name'], 'verdict': 2, 'counter_delta': {}}
        result = super().packet(packet['Name'], winner)
        return {key: result[key] for key in ('packet', 'verdict', 'counter_delta')}

    def remove(self, id, publish=True):
        if not any(r['id'] == id for r in self.installed):
            return False
        super().remove(id, publish)
        return True

    def full(self, rules, fault=''):
        seen = {}
        for index, r in enumerate(rules):
            if r.get('id') and r['id'] in seen:
                first = seen[r['id']]
                return self.reject('duplicate_id', 'duplicate ID '+json.dumps(r['id'])+f' at index {first} and index {index}; batch not published', added=0, failed=1,
                                   conflicts=[dict(id=r['id'], index=first), dict(id=r['id'], index=index)])
            if r.get('id'):
                seen[r['id']] = index
        # The inherited model supplies the original protocol-6 preflight and
        # state transition. This extension adds formerly unmodelled closeout paths.
        if self.protocol < 8 and self.withdrawal and fault == 'trie_delete':
            return self.reject('withdrawal_pending', 'pending CIDR withdrawal', 500, added=0, failed=1)
        rejected, accepted, accepted_indices = [], [], []
        for index, r in enumerate(rules):
            reason = self.family_reason(r)
            if reason:
                reason = self.family_reason(r, prepared=True)
                item = dict(id=r.get('id', ''), reason=reason)
                if not item['id']: item['index'] = index
                rejected.append((index, item))
            else:
                accepted.append(r)
                accepted_indices.append(index)
        normalized_rules = [normalized(r) for r in accepted]
        saved = copy.deepcopy(self.__dict__) if self.protocol >= 8 else None
        before = self.prefix_set()
        status, body = super().full(normalized_rules, fault)
        if status == 200:
            body['failed'] += len(rejected)
            pending = list(range(len(accepted)))
            for item in body['rejected']:
                position = item.get('index')
                if position is None:
                    position = next(i for i in pending if accepted[i].get('id', '') == item.get('id', ''))
                pending.remove(position)
                original = accepted_indices[position]
                if 'index' in item: item['index'] = original
                rejected.append((original, item))
            body['rejected'] = [item for _, item in sorted(rejected, key=lambda row: row[0])]
            prefixes = self.prefix_set()
            if saved is not None:
                if not self.apply_prefixes(self.slot, before, prefixes, fault):
                    self.abort_prefixes(saved)
                    return 500, dict(added=body['added'], error='injected closeout trie delete', failed=body['failed']+1)
                # R5c: old-side failure is logged, with publication retained.
                self.apply_prefixes(1-self.slot, before, prefixes, fault)
            else:
                self.prefix_copies[self.slot] = prefixes
            self.withdrawal = False
        elif saved is not None and status == 500 and fault == 'full_step1_delete':
            # prepareAtomicShadow failed inside DoAtomicSync's local abort.
            self.prefix_known[1-self.slot] = False
        return status, body

    def add(self, rule, capacity=None, publish=True):
        rule = normalized(rule)
        owner = next((r for r in self.installed if r.get('logical_id') == rule.get('logical_id') and r['id'] != rule['id']), None)
        if owner and not any(r['id'] == rule['id'] for r in self.installed):
            return 'duplicate_logical_id', owner['id']
        code, error = super().add(rule, capacity, publish)
        # api/cidr_rules.go:addCIDRRule returns mutationError on changed replay;
        # AddRulesBatch exposes its Message in the per-item Error field.
        if cidr(rule) and code == 'content_different':
            error = 'rule content differs'
        return code, error

    def preflight(self, rules):
        rules = [normalized(r) for r in rules]
        return super().preflight(rules)

    def prefix_set(self):
        return {(field, r[field]) for r in self.installed
                for field in ('src_cidr', 'dst_cidr') if r.get(field)}

    def apply_prefixes(self, slot, before, want, fault=''):
        # Manager.Apply: known copies use the transaction delta; unknown copies
        # enumerate actual content. Keep the abstraction at table membership.
        have = before if self.prefix_known[slot] else self.prefix_copies[slot].copy()
        self.prefix_known[slot] = False
        for field, version in (('src_cidr', 4), ('dst_cidr', 4), ('src_cidr', 6), ('dst_cidr', 6)):
            table = lambda entries: {p for p in entries if p[0] == field and ipaddress.ip_network(p[1]).version == version}
            remove, add = table(have-want), table(want-have)
            if remove and fault == 'trie_delete':
                return False
            self.prefix_copies[slot].difference_update(remove)
            self.prefix_copies[slot].update(add)
        self.prefix_known[slot] = True
        return True

    def abort_prefixes(self, saved):
        # Undo unpublished policy and reservations, never trie writes or IDs.
        copies, known, next_id = self.prefix_copies, self.prefix_known, self.next_prefix
        self.__dict__ = saved
        self.prefix_copies, self.prefix_known, self.next_prefix = copies, known, next_id

    def commit(self, groups, fault=''):
        probe, prefix = P6State(self.protocol), []
        affected = any(self.family_reason(r) for g in groups for r in [g['key'], *g['rules']])
        for i, group in enumerate(groups if affected else []):
            prefix.append(dict(key=group['key'], rules=[]))
            for member, rule in enumerate([group['key'], *group['rules']]):
                if member: prefix[-1]['rules'].append(rule)
                reason = self.family_reason(rule, prepared=bool(member)) if not member or rule.get('id') else None
                if reason:
                    return 400, dict(code='validation_rejected', error=reason, groups=[dict(index=i, code='validation_rejected', error=reason)])
                # Reuse frozen request-local diagnostics, stopping before writes.
                status, body = P5State.commit(probe, prefix, 'c-2')
                if body['code'] in ('validation_rejected', 'duplicate_id', 'duplicate_logical_id'):
                    return status, body
            if body['code'] == 'condition_capacity': return status, body
        if self.protocol >= 8:
            old, shadow = self.prefix_set(), 1-self.slot
            # Reuse inherited preflight/admission through the pre-reservation
            # c-3 stop. No live state or prefix ID is changed by this probe.
            if fault == 'capacity_one':
                _, admission = P6State.commit(copy.deepcopy(self), groups, fault)
                if admission.get('code') == 'table_full':
                    return super().commit(groups, fault)
            probe = copy.deepcopy(self)
            # TD-112: payment-failure admission retains the inherited domain.
            early = fault if fault in ('capacity_one_payment_failure', 'c-2', 'R0', 'c-3') else 'c-3'
            _, check = P6State.commit(probe, groups, early)
            if check.get('error') != 'injected c-3' or fault == 'c-3':
                return super().commit(groups, fault)
            # C1 CatchUp/Align precedes reserveCommitGroups.
            if not self.prefix_known[shadow] and not self.apply_prefixes(shadow, set(), old, fault):
                return 500, dict(code='commit_failed', error='injected closeout trie delete', groups=[])
            saved = copy.deepcopy(self.__dict__)
            status, body = super().commit(groups, fault)
            if fault in ('c-4', 'c-5', 'c-6'):
                self.prefix_known[shadow] = False
                return status, body
            declared = {groupkey(g['key']) for g in groups}
            target = [r for r in saved['installed'] if groupkey(r) not in declared]+[r for g in groups for r in g['rules']]
            new = {(field, r[field]) for r in target for field in ('src_cidr', 'dst_cidr') if r.get(field)}
            if body.get('code') == 'committed' or fault == 'c-7':
                if not self.apply_prefixes(shadow, old, new, fault):
                    self.abort_prefixes(saved)
                    return 500, dict(code='commit_failed', error='injected closeout trie delete', groups=[])
                if fault == 'c-7':
                    self.prefix_known[shadow] = False
                elif body['receipt'] == 'deferred':
                    # installCommitMemory releases references before Rc.
                    self.tries()
                    self.prefix_known[1-shadow] = False
                else:
                    self.apply_prefixes(1-shadow, old, new, fault)
            return status, body
        # installCommitMemory records exiting prefix references; after Rc,
        # settleCommitPrefixesLocked releases them. Manager.releaseLocked retains
        # failed last-reference trie deletes until ClearWithdrawals succeeds.
        def prefixes():
            return {(field, r[field]) for r in self.installed
                    for field in ('src_cidr', 'dst_cidr') if r.get(field)}
        before = prefixes()
        if (self.withdrawal and fault == 'trie_delete'
                and any(g['key']['kind'] == 'cidr' for g in groups)):
            # DoCommitRules: preflight/admission and unchanged precede step 2;
            # cidr.Manager.ClearWithdrawals fails before shadow/publication.
            # Reuse the inherited c-2 stop to run those pure checks in order.
            # The existing boolean abstraction has no pending-prefix identities,
            # so use the same withdrawal error summary as full(), without state.
            status, body = super().commit(groups, 'c-2')
            if status == 500 and body.get('code') == 'withdrawal_pending':
                body['error'] = 'pending CIDR withdrawal'
            return status, body
        status, body = super().commit(groups, fault)
        # api/commit.go:DoCommitRules returns unchanged before step 2. Only a
        # changed, admitted plan reaches ClearWithdrawals, and HasCIDR covers
        # every declared group (commit_preflight.go:preflightCommit). Its clear
        # survives later R0/c-3..c-9 failures; c-2/trie-delete failure preserves debt.
        reached_step_two = (body.get('code') == 'committed' or
                            status == 500 and body.get('code') in
                            ('withdrawal_pending', 'quiescence_failed', 'commit_failed'))
        if (reached_step_two and any(g['key']['kind'] == 'cidr' for g in groups)
                and fault not in ('c-2', 'trie_delete')):
            self.withdrawal = False
        if (fault == 'trie_delete' and status == 200 and body.get('receipt') == 'confirmed'
                and before - prefixes()):
            self.withdrawal = True
        return status, body

    def wl_publish(self):
        self.publish()
        config = self.maps[('config_a', 'config_b')[self.config_slot]]
        bitmap = 0
        for rule in self.whitelist:
            bitmap |= 1 << combo(rule)
        config[LE32(1)], config[LE32(3)], config[LE32(8)] = LE64(len(self.whitelist)), LE64(bitmap), LE64(self.wl_slot)

    def wl_request(self, step):
        method, path, body = step['Method'], step['Path'], step.get('Body', {})
        if method == 'GET':
            return 200, self.whitelist_response()
        full = path == '/api/v1/sync/whitelist'
        if method == 'DELETE':
            ids = body['ids'] if path.endswith('/batch') else [path.rsplit('/', 1)[1]]
            deleted = 0
            for id in ids:
                entry = next((r for r in self.whitelist if r['id'] == id), None)
                if entry:
                    self.whitelist.remove(entry)
                    deleted += 1
            if deleted:
                self.wl_publish()
            if path.endswith('/batch'):
                return 200, dict(success=True, deleted=deleted, failed=len(ids)-deleted)
            if not deleted:
                return 404, dict(code='whitelist_not_found', error='Whitelist entry not found')
            return 200, dict(success=True, message='Whitelist entry deleted')
        incoming = body['entries'] if full or path.endswith('/batch') else [body]
        prepared, seen_ids, seen_keys = [], set(), set()
        for r in incoming:
            if full:
                id = r.get('id', '')
                if not id:
                    return 400, dict(error='whitelist entry with empty ID rejected')
                if id in seen_ids:
                    return 400, dict(error='duplicate whitelist ID in sync batch: ' + id)
            reason = self.family_reason(r)
            if reason: return 400, dict(error='invalid whitelist entry '+r.get('id', '')+': '+reason)
            r = {k: v for k, v in normalized(r).items() if k != 'action'}
            if full:
                key = groupkey(r)
                if key in seen_keys:
                    return 400, dict(error='duplicate whitelist key in sync batch for ID ' + id)
                seen_ids.add(id)
                seen_keys.add(key)
            prepared.append(r)
        incoming = prepared
        if full:
            self.whitelist = incoming
            self.wl_slot = 1-self.wl_slot
            self.wl_publish()
            return 200, dict(total=len(incoming), failed=0)
        # Explicit IDs are required by this harness's deterministic input domain.
        assert all(r.get('id') for r in incoming), 'successful whitelist input needs an explicit ID'
        dedup = {}
        for r in incoming:
            dedup[r['id']] = r
        incoming = list(dedup.values())
        for r in incoming:
            owner = next((old for old in self.whitelist if groupkey(old) == groupkey(r) and old['id'] != r['id']), None)
            if owner:
                message = ('key already owned by id ' + owner['id']) if path.endswith('/batch') else ('whitelist key already exists under id ' + owner['id'])
                return 409, dict(code='key_occupied', existing_id=owner['id'], error=message)
        changed = 0
        for r in incoming:
            old = next((old for old in self.whitelist if old['id'] == r['id']), None)
            if old and groupkey(old) == groupkey(r):
                continue
            if old:
                self.whitelist.remove(old)
            self.whitelist.append(r)
            changed += 1
        if changed:
            self.wl_publish()
        if path.endswith('/batch'):
            return 200, dict(success=True, added=changed)
        return 200, dict(success=True, id=incoming[0]['id'], message='Whitelist entry added' if changed else 'Whitelist entry unchanged (idempotent)')

    def request(self, step):
        if self.protocol == 6:
            return self.request_legacy(step)
        method, path = step['Method'], step.get('Path', '')
        if method == 'RESTART':
            self.__init__(self.protocol, self.cpus, self.packet_cpu)
            replies = []
            for request in step['Requests']:
                status, body = self.request(request)
                replies.append(dict(status=status, body=body))
            return None, dict(startup_success=True, replies=replies)
        if (method, path) == ('GET', '/'):
            return 200, dict(name='XDrop Agent', version='dev', sync_protocol=self.protocol)
        if (method, path) == ('GET', '/api/v1/health'):
            if self.rules_synced and self.whitelist_synced:
                return 200, dict(status='healthy')
            return 200, dict(status='degraded', reason='awaiting_full_sync',
                             rules_synced=self.rules_synced, whitelist_synced=self.whitelist_synced)
        retained = {('GET', '/api/v1/rules'), ('GET', '/api/v1/whitelist'),
                    ('GET', '/api/v1/stats'), ('GET', '/api/v1/stats/cpu'),
                    ('POST', '/api/v1/rules/commit'), ('POST', '/api/v1/sync/atomic'),
                    ('POST', '/api/v1/sync/whitelist')}
        if method.startswith('STARTUP_'):
            return self.request_legacy(step)
        if (method, path) not in retained:
            return 404, '404 page not found'
        if step.get('Fault') == 'active_config_lookup' and path == '/api/v1/rules/commit':
            # commit.go:writeCommitConfig aborts before the selector flip.
            status, body = self.commit(step['Body']['groups'], 'c-6')
            assert status == 500
            body['error'] = 'read active config 0: lookup: bad file descriptor'
        else:
            status, body = self.request_legacy(step)
        if self.protocol >= 8 and isinstance(body, dict):
            body.pop('withdrawal_pending', None)
        if 200 <= status < 300:
            if path == '/api/v1/sync/atomic': self.rules_synced = True
            if path == '/api/v1/sync/whitelist': self.whitelist_synced = True
        return status, body

    def request_legacy(self, step):
        method, path = step['Method'], step.get('Path', '')
        if '/whitelist' in path:
            return self.wl_request(step)
        if method == 'STARTUP_FAILURE':
            return None, {'startup_refused': True}
        if method == 'STARTUP_CLEAR_FAILURE':
            return None, {'startup_refused': True}
        if method == 'GET':
            if path == '/api/v1/rules':
                return 200, self.installed_response()
            if path == '/api/v1/health':
                return 200, {'status': 'healthy'}
            if path == '/api/v1/stats':
                return 200, self.stats_response()
            return super().request(step)
        if method == 'DELETE':
            # Only trie withdrawal is modelled. Never predict a successful BPF
            # delete when a future batch input asks for an unmodelled failure.
            if path.endswith('/batch') and step.get('Fault', '') not in ('', 'trie_delete'):
                raise ValueError('unmodelled batch-delete fault: ' + repr(step['Fault']))
            ids = step['Body']['ids'] if path.endswith('/batch') else [path.rsplit('/', 1)[1]]
            for id in ids:
                old = next((r for r in self.installed if r['id'] == id), None)
                if old and (extended(old) or len([r for r in self.installed if groupkey(r) == groupkey(old)]) > 1):
                    return self.reject('condition_group_required', 'condition five-tuple requires a whole-group write', key=identity(old))
            results = []
            for id in ids:
                removed = self.remove(id, False)
                results.append(dict(id=id, code='success' if removed else 'rule_not_found'))
            deleted = sum(r['code'] == 'success' for r in results)
            if deleted:
                self.publish()
            if step.get('Fault') == 'trie_delete' and deleted:
                self.withdrawal = True
            if path.endswith('/batch'):
                # DeleteRulesBatch: missing IDs are not failures; deletePureRule
                # errors are internal_error results (not yet modelled here).
                failed = sum(r['code'] not in ('success', 'rule_not_found') for r in results)
                return 200, dict(success=True, deleted=deleted, failed=failed, results=results, withdrawal_pending=self.withdrawal)
            if not deleted:
                return self.reject('rule_not_found', 'Rule not found', 404)
            return 200, dict(success=True, message='Rule deleted', code='success', withdrawal_pending=self.withdrawal)
        status, body = super().request(step)
        # exactReplayLocked detects ownership before writing; mutationReply
        # emits a 409, whereas the inherited p4 request maps this code to 200.
        if method == 'POST' and path == '/api/v1/rules' and body.get('code') == 'duplicate_logical_id':
            owner = next(r['id'] for r in self.installed if r.get('logical_id') == step['Body'].get('logical_id'))
            status, body = self.reject('duplicate_logical_id', 'logical ID is held by another rule', existing_id=owner)
        if isinstance(body, dict) and 'withdrawal_pending' in body:
            body['withdrawal_pending'] = self.withdrawal
        return status, body

    def run_closeout(self, scene, oracle=None):
        records, inputs = {}, {}
        for step in scene['Steps']:
            case = scene['Name'] + '/' + step['Name']
            status, body = self.request(step)
            if step['Method'] == 'RESTART' and self.protocol == 6:
                body = {'startup_success': True}
            # Welcome's version/features are deliberately not cells (PLAN §4-6).
            if step.get('Path') == '/':
                body = {'sync_protocol': body['sync_protocol']}
            inputs[case] = dict(Rules=copy.deepcopy(self.installed),
                               Whitelist=[dict(r, logical_id=0x70000000+i, action='drop') for i, r in enumerate(self.whitelist)],
                               Packets=step['Packets'])
            rec = dict(family=scene['Family'], path=step.get('Path', ''), status=status, body=body,
                       installed=self.installed_response(), whitelist=self.whitelist_response())
            predictions = []
            seeded = False
            for index, packet in enumerate(step['Packets']):
                if oracle is None:
                    continue
                if packet.get('SeedEmpty') and not seeded:
                    self.seed_rate()
                    seeded = True
                predictions.append(self.project_packet(packet, oracle[case][index]))
            rec['packets'] = predictions
            rec['installed_after'] = self.installed_response()
            rec['stats'] = self.stats_response()
            records[case] = rec
        return records, inputs


def legal_serial(single, commits, full, whitelist):
    """Enumerate all interleavings, prove each (i,j) has one logical terminal."""
    by_pair, witnesses = {}, {}
    n, m = len(single), len(commits)
    for a_positions in itertools.combinations(range(n+m), n):
        order = ['C']*(n+m)
        for p in a_positions:
            order[p] = 'A'
        for cut in range(2, n+m+1):
            i, j = order[:cut].count('A'), order[:cut].count('C')
            if i < 1 or j < 1:
                continue
            state = State()
            replies, indexes = {}, {'A': 0, 'C': 0}
            for position in range(n+m+1):
                if position == cut:
                    replies['F'] = state.request(full)
                if position == n+m:
                    break
                writer = order[position]
                index = indexes[writer]
                step = (single if writer == 'A' else commits)[index]
                replies[writer+str(index)] = state.request(step)
                indexes[writer] += 1
            replies['W'] = state.request(whitelist)
            terminal = dict(installed=state.installed_response(), whitelist=state.whitelist_response())
            key = (i, j)
            if key in by_pair and by_pair[key] != terminal:
                raise AssertionError('STOP S7 inter-writer order changes terminal for ' + repr(key))
            by_pair[key] = terminal
            witnesses.setdefault(key, []).append(replies)
    assert set(by_pair) == set(itertools.product(range(1, n+1), range(1, m+1)))
    return [dict(i=i, j=j, terminal=by_pair[i, j], replies=witnesses[i, j]) for i, j in sorted(by_pair)]
