#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from adapt_historical import adapt, snapshot, verify_unchanged, historical_accepts, historical_expectation
from generate_closeout_scenarios import (characterizations, concurrency, counts, full, packet,
                                       rule, step, track_b_inputs, track_b_state)
from reference_closeout import State, LE32, identity
from track_b import config_from_example


class ModelTests(unittest.TestCase):
    def test_protocol9_syntax_precedes_family(self):
        def outcome(command):
            try:
                return ('return', State().request(command))
            except ValueError:
                return ('raise', ValueError)
        for kind in ('exact', 'CIDR', 'whitelist'):
            for side in ('src', 'dst'):
                with self.subTest(kind=kind, invalid_side=side):
                    suffix = '_cidr' if kind == 'CIDR' else '_ip'
                    mapped = '::ffff:192.0.2.0/120' if kind == 'CIDR' else '::ffff:192.0.2.1'
                    plain = '192.0.2.0/24' if kind == 'CIDR' else '192.0.2.1'
                    invalid = 'bad-prefix' if kind == 'CIDR' else 'invalid'
                    other = 'dst' if side == 'src' else 'src'
                    incoming = dict(id='bad', protocol='tcp')
                    incoming.update({side+suffix: invalid, other+suffix: mapped})
                    if kind != 'whitelist':
                        incoming.update(logical_id=901, action='drop')
                    control = dict(incoming, **{other+suffix: plain})
                    def command(r):
                        return step('syntax', 'POST', '/api/v1/sync/'+('whitelist' if kind == 'whitelist' else 'atomic'),
                                    {('entries' if kind == 'whitelist' else 'rules'): [r]})
                    self.assertIsNone(State().family_reason(incoming))
                    self.assertIsNone(State().family_reason(control))
                    actual, expected = outcome(command(incoming)), outcome(command(control))
                    self.assertEqual(actual, expected)
                    self.assertEqual(expected, ('raise', ValueError))
                    print('AF_MODEL_SYNTAX case='+kind+'/'+side+' family_reason=None mapped=ValueError plain_v4=ValueError')

    def test_protocol9_rejection_original_indices(self):
        incoming = [rule('bad', 901, '::ffff:192.0.2.1'), rule('ordinary', 0, '198.51.100.1'), rule('', 0, '192.0.2.2')]
        parent = dict(added=0, failed=2, rejected=[dict(id='', index=1, reason='ordinary failure'), dict(id='ordinary', reason='ordinary failure')])
        with patch('reference_closeout.P6State.full', return_value=(200, parent)):
            status, body = State().full(incoming)
        self.assertEqual((status, body['failed']), (200, 3))
        self.assertEqual([r['id'] for r in body['rejected']], ['bad', 'ordinary', ''])
        self.assertEqual(body['rejected'][2]['index'], 2)
        self.assertNotIn('index', body['rejected'][1])

    def test_protocol9_rejection_input_order(self):
        bad = rule('bad', 901, '::ffff:192.0.2.1')
        ordinary = rule('ordinary', 0, '198.51.100.1')
        good = rule('good', 903, '192.0.2.2')
        reasons = [dict(id='bad', reason='invalid src_ip: IPv4-mapped IPv6 address ::ffff:192.0.2.1; write the IPv4 address 192.0.2.1'),
                   dict(id='ordinary', reason='logical_id must be nonzero')]
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                state = State()
                incoming = [ordinary, bad, good] if reverse else [bad, ordinary, good]
                status, body = state.request(full('rejection-order', incoming))
                self.assertEqual((status, body['added'], body['failed']), (200, 1, 2))
                self.assertEqual(body['rejected'], list(reversed(reasons)) if reverse else reasons)
                self.assertEqual([r['id'] for r in state.installed], ['good'])
                print('AF_MODEL_REJECTED_ORDER reverse='+str(reverse)+' rejected='+json.dumps(body['rejected']))

    def test_migration_predicates_not_code_aliases(self):
        self.assertTrue(historical_accepts('invalid', 400, {'code': 'validation_rejected'}))
        self.assertTrue(historical_accepts('success', 200, {'code': 'updated', 'success': True}))
        self.assertTrue(historical_accepts('deferred', 200, {'code': 'committed', 'receipt': 'deferred'}))
        self.assertFalse(historical_accepts('success', 409, {'code': 'condition_group_required'}))
        self.assertEqual(historical_expectation('scenarios_p4.json', {'ExpectP3': 'success', 'ExpectP4': 'invalid'}), (4, 'ExpectP4', 'invalid'))

    def test_missing_delete(self):
        code, body = State(protocol=6).request(step('missing', 'DELETE', '/api/v1/rules/missing', packets=[]))
        self.assertEqual((code, body['code']), (404, 'rule_not_found'))

    def test_batch_delete_missing_is_not_failure(self):
        state = State(protocol=6)
        self.assertEqual(state.request(step('add', 'POST', '/api/v1/rules', rule('present', 91)))[0], 200)
        status, body = state.request(step('delete', 'DELETE', '/api/v1/rules/batch', {'ids': ['present', 'absent']}))
        self.assertEqual((status, body['deleted'], body['failed']), (200, 1, 0))
        self.assertEqual(body['results'], [{'id': 'present', 'code': 'success'}, {'id': 'absent', 'code': 'rule_not_found'}])
        self.assertTrue(historical_accepts('success', status, body))
        self.assertEqual(state.installed, [])
        self.assertEqual(state.request(step('delete', 'DELETE', '/api/v1/rules/batch', {'ids': ['absent']}))[1]['failed'], 0)

    def test_duplicate_logical_id_rejects_without_writing(self):
        state = State(protocol=6)
        self.assertEqual(state.request(step('add', 'POST', '/api/v1/rules', rule('a', 92)))[0], 200)
        before = copy.deepcopy(state.installed)
        status, body = state.request(step('duplicate', 'POST', '/api/v1/rules', rule('b', 92, '10.92.1.1')))
        self.assertEqual((status, body), (409, dict(code='duplicate_logical_id', error='logical ID is held by another rule', existing_id='a', withdrawal_pending=False)))
        self.assertEqual(state.installed, before)
        self.assertTrue(historical_accepts('duplicate_logical_id', status, body))

    def test_unmodelled_batch_delete_fault_stops_generation(self):
        for fault in ('map_delete', 'active_config_lookup', 'future_delete_failure'):
            with self.subTest(fault=fault):
                state = State(protocol=6)
                state.request(step('add', 'POST', '/api/v1/rules', rule('present', 91)))
                before = copy.deepcopy(state.__dict__)
                scene = dict(Name='batch-delete-fault', Family='selftest', Steps=[
                    step('delete', 'DELETE', '/api/v1/rules/batch', {'ids': ['present', 'absent']}, Fault=fault)])
                with self.assertRaisesRegex(ValueError, 'unmodelled batch-delete fault'):
                    state.run_closeout(scene)
                self.assertEqual(state.__dict__, before)

    def test_changed_cidr_batch_replay_carries_error(self):
        state = State(protocol=6)
        r = dict(id='cidr', logical_id=93, src_cidr='10.93.0.0/16', protocol='tcp', action='drop')
        self.assertEqual(state.request(step('add', 'POST', '/api/v1/rules/batch', {'rules': [r]}))[1]['failed'], 0)
        before = copy.deepcopy(state.installed)
        status, body = state.request(step('replay', 'POST', '/api/v1/rules/batch', {'rules': [dict(r, logical_id=94)]}))
        self.assertEqual((status, body['added'], body['failed']), (200, 0, 1))
        self.assertEqual(body['results'], [dict(id='cidr', code='content_different', error='rule content differs')])
        self.assertEqual(state.installed, before)
        self.assertTrue(historical_accepts('logical_id_replay', status, body))

    def test_commit_cidr_withdrawal_fault_and_payment(self):
        cidr_rule = dict(id='cidr', logical_id=93, src_cidr='10.93.0.0/16', protocol='tcp', action='drop')
        cases = [('cidr_fault', cidr_rule, 'trie_delete', False, True),
                 ('cidr_no_fault', cidr_rule, '', False, False),
                 ('exact_fault', rule('exact', 93), 'trie_delete', False, False),
                 ('shared_prefix', cidr_rule, 'trie_delete', True, False)]
        for name, removed, fault, shared, pending in cases:
            with self.subTest(name=name):
                state = State(protocol=7)
                keep = [dict(cidr_rule, id='keep', logical_id=94, dst_port=443)] if shared else []
                self.assertEqual(state.request(full('seed', [removed]+keep))[0], 200)
                status, body = state.request(step('retire', 'POST', '/api/v1/rules/commit',
                    dict(groups=[dict(key=identity(removed), rules=[])]), Fault=fault))
                self.assertEqual((status, body['code'], body['receipt']), (200, 'committed', 'confirmed'))
                self.assertEqual(body['withdrawal_pending'], pending)
                self.assertEqual([r['id'] for r in state.installed], [r['id'] for r in keep])
                status, body = state.request(full('paid', []))
                self.assertEqual((status, body['withdrawal_pending'], state.withdrawal), (200, False, False))
        print(f'CLOSEOUT_WITHDRAWAL_MODEL controls={len(cases)} pending_positive=1 negatives=3 paid=4')

    def test_commit_clears_withdrawal_at_step_two(self):
        a = dict(id='a', logical_id=93, src_cidr='10.93.0.0/24', protocol='tcp', action='drop')
        b = dict(id='b', logical_id=94, src_cidr='10.94.0.0/24', protocol='tcp', action='drop')
        def request(r, members, fault=''):
            return step('commit', 'POST', '/api/v1/rules/commit',
                        dict(groups=[dict(key=identity(r), rules=members)]), Fault=fault)
        state = State(protocol=7)
        self.assertEqual(state.request(request(a, [a]))[0], 200)
        status, body = state.request(request(a, [], 'trie_delete'))
        self.assertEqual((status, body['receipt'], body['withdrawal_pending']), (200, 'confirmed', True))
        self.assertEqual(state.installed, [])
        cases = [
            ('changed_cidr', request(b, [b]), 200, 'committed', False),
            ('unchanged', request(a, []), 200, 'unchanged', True),
            ('exact_only', request(rule('exact', 94), [rule('exact', 94)]), 200, 'committed', True),
            ('step_two_failure', request(b, [b], 'c-2'), 500, 'withdrawal_pending', True),
            ('preflight_failure', request(b, [dict(b, logical_id=0)]), 400, 'validation_rejected', True),
            ('later_receipt_failure', request(b, [b], 'R0'), 500, 'quiescence_failed', False),
            ('later_build_failure', request(b, [b], 'c-3'), 500, 'commit_failed', False),
        ]
        for name, command, expected_status, code, pending in cases:
            with self.subTest(name=name):
                branch = copy.deepcopy(state)
                fields = set(branch.__dict__)
                status, body = branch.request(command)
                self.assertEqual((status, body['code'], body['withdrawal_pending'], branch.withdrawal),
                                 (expected_status, code, pending, pending))
                self.assertEqual(set(branch.__dict__), fields)
                if name == 'changed_cidr':
                    self.assertEqual([r['id'] for r in branch.installed], ['b'])
        print(f'CLOSEOUT_COMMIT_PAYMENT_MODEL controls={len(cases)} clears=3 preserves=4 new_state=0')

    def test_commit_repeated_withdrawal_failure_precedes_publication(self):
        a = dict(id='a', logical_id=93, src_cidr='10.93.0.0/24', protocol='tcp', action='drop')
        b = dict(id='b', logical_id=94, src_cidr='10.94.0.0/24', protocol='tcp', action='drop')
        def request(r, members, fault='trie_delete'):
            return step('commit', 'POST', '/api/v1/rules/commit',
                        dict(groups=[dict(key=identity(r), rules=members)]), Fault=fault)
        state = State(protocol=7)
        self.assertEqual(state.request(request(a, [a], ''))[0], 200)
        self.assertTrue(state.request(request(a, []))[1]['withdrawal_pending'])
        before = copy.deepcopy(state.__dict__)
        status, body = state.request(request(b, [b]))
        self.assertEqual((status, body), (500, dict(code='withdrawal_pending',
            error='pending CIDR withdrawal', groups=[], withdrawal_pending=True)))
        self.assertEqual(state.__dict__, before)
        for name, command, expected_status, code in (
                ('preflight', request(b, [dict(b, logical_id=0)]), 400, 'validation_rejected'),
                ('unchanged', request(a, []), 200, 'unchanged')):
            with self.subTest(name=name):
                status, body = state.request(command)
                self.assertEqual((status, body['code'], body['withdrawal_pending']), (expected_status, code, True))
                self.assertEqual(state.__dict__, before)
        for name, branch, incoming, pending in (
                ('exact_only', copy.deepcopy(state), rule('exact', 95), True),
                ('no_debt', State(protocol=7), b, False)):
            with self.subTest(name=name):
                control = copy.deepcopy(branch)
                self.assertEqual(control.request(request(incoming, [incoming], ''))[0], 200)
                fields = set(control.__dict__)
                status, body = branch.request(request(incoming, [incoming]))
                self.assertEqual((status, body['code'], body['withdrawal_pending']), (200, 'committed', pending))
                self.assertEqual([r['id'] for r in branch.installed], [incoming['id']])
                self.assertEqual(set(branch.__dict__), fields)
        print('CLOSEOUT_COMMIT_RETRY_MODEL controls=5 rejection=1 preflight_first=1 unchanged_first=1 bypasses=2 state_equal=3 new_state=0')

    def test_protocol8_atomic_shadow_delete_failure_and_controls(self):
        from generate_closeout_scenarios import commit
        p = dict(id='p', logical_id=93, src_cidr='10.93.0.0/24', protocol='tcp', action='drop')
        q = dict(id='q', logical_id=94, src_cidr='10.94.0.0/24', protocol='tcp', action='drop')
        state = State()
        status, body = state.request(commit('seed', [p], []))
        self.assertEqual((status, body['code'], body['receipt']), (200, 'committed', 'confirmed'))
        self.assertEqual(state.prefix_copies, [{('src_cidr', p['src_cidr'])}]*2)
        state.maps['id_counts'][LE32(93)] = [7, 3]
        state.maps['stats'][LE32(0)] = [11]
        state.maps['stats'][LE32(1)] = [3]
        state.maps['stats'][LE32(2)] = [8]
        before = copy.deepcopy(state.__dict__)
        installed, stats = state.installed_response(), state.stats_response()
        self.assertEqual(state.request(full('replace', [q], Fault='trie_delete')),
                         (500, dict(added=1, error='injected closeout trie delete', failed=1)))
        for field, expected in dict(installed=[p], groups=[[p]], prefixes={('src', '10.93.0.0/24'): 1},
                rules_synced=False, whitelist_synced=False, whitelist=[], slot=1, config_slot=1, wl_slot=0,
                withdrawal=False, pending=set(), times={}, now=10000000000,
                prefix_copies=[{('src_cidr', '10.93.0.0/24')}, {('src_cidr', '10.93.0.0/24')}]).items():
            with self.subTest(preserved=field): self.assertEqual(getattr(state, field), expected)
        self.assertEqual(state.maps, before['maps'])
        self.assertEqual(state.maps['stats'], {LE32(i): [n] for i, n in enumerate([11, 3, 8, 0, 0, 0])})
        self.assertEqual(state.maps['id_counts'], {LE32(93): [7, 3]})
        with self.subTest(changed='next_prefix'): self.assertEqual(state.next_prefix, 3)
        with self.subTest(changed='prefix_known'): self.assertEqual(state.prefix_known, [False, True])
        self.assertEqual((state.installed_response(), state.stats_response()), (installed, stats))
        self.assertFalse(state.rules_synced)
        self.assertEqual(set(state.__dict__), set(before))
        good = dict(success=True, added=1, failed=0, rules=0, cidr_rules=1, rejected=[])
        self.assertEqual(state.request(full('replace-ok', [q])), (200, good))
        self.assertEqual([r['id'] for r in state.installed], ['q'])
        self.assertEqual(state.prefix_copies[state.slot], {('src_cidr', q['src_cidr'])})
        self.assertTrue(state.rules_synced)
        for name, seeded, incoming in (('same-prefix', copy.deepcopy(before), [dict(p, id='q', logical_id=94)]),
                                       ('shadow-empty', State().__dict__, [q])):
            with self.subTest(name=name):
                branch = State()
                branch.__dict__ = copy.deepcopy(seeded)
                fields = set(branch.__dict__)
                self.assertEqual(branch.request(full(name, incoming, Fault='trie_delete')), (200, good))
                self.assertEqual([r['id'] for r in branch.installed], ['q'])
                self.assertEqual(set(branch.__dict__), fields)
        print('CLOSEOUT_ATOMIC_DELETE_MODEL failure=1 no_fault=1 no_delete_controls=2 old_policy_and_counts=1 new_state=0')

    # PLAN §三-2: responses and copy/ID transitions below are literal expectations.
    def td096_rules(self, number, p_field='src_cidr', p_net='fd00:96:1::/64',
                    q_field='src_cidr', q_net='10.96.2.0/24'):
        p = dict(id=f'td096-x{number}-p', logical_id=96000+number*10+1, protocol='tcp', action='drop', **{p_field: p_net})
        q = dict(id=f'td096-x{number}-q', logical_id=96000+number*10+2, protocol='tcp', action='drop', **{q_field: q_net})
        return p, q, (p_field, p_net), (q_field, q_net)

    def td096_commit(self, name, p, q=None, fault=''):
        groups = [dict(key=identity(p), rules=[] if q else [p])]
        if q: groups.append(dict(key=identity(q), rules=[q]))
        return step(name, 'POST', '/api/v1/rules/commit', dict(groups=groups), [], Fault=fault)

    def td096_check(self, state, number, index, command, response, copies, known, next_id):
        status, body = state.request(command)
        for field, actual, expected in (
                ('status', status, response[0]), ('body', body, response[1]),
                ('copies', state.prefix_copies, copies), ('known', state.prefix_known, known),
                ('next_prefix', state.next_prefix, next_id)):
            with self.subTest(leaf=f'X{number}.step{index}.{field}'):
                self.assertEqual(actual, expected)
                authority = f'PLAN-三-2-X{number}' if number <= 9 else f'ruling-2-R2-{number-9}'
                print(f'TD096_G1 leaf=X{number}.step{index}.{field} authority={authority} result=PASS')

    def td096_reply(self, kind):
        # Constants come from PLAN §三-2, never from a State helper.
        return {
            'A': (200, dict(added=1, cidr_rules=1, failed=0, rejected=[], rules=0, success=True)),
            'AF': (500, dict(added=1, error='injected closeout trie delete', failed=1)),
            'CF': (500, dict(code='commit_failed', error='injected closeout trie delete', groups=[])),
            'C7': (500, dict(code='commit_failed', error='injected c-7', groups=[])),
            'created': (200, dict(code='committed', receipt='confirmed', groups=[dict(index=0, result='created')])),
            'swap': (200, dict(code='committed', receipt='confirmed', groups=[dict(index=0, result='deleted'), dict(index=1, result='created')])),
            'deferred': (200, dict(code='committed', receipt='deferred', groups=[dict(index=0, result='deleted'), dict(index=1, result='created')]))
        }[kind]

    def td096_atomic_sequence(self, number, p_field, p_net, q_field, q_net, partial):
        s = State()
        p, q, P, Q = self.td096_rules(number, p_field, p_net, q_field, q_net)
        self.td096_check(s, number, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, number, 2, full('replace', [q], [], Fault='trie_delete'), self.td096_reply('AF'),
                          [{P, Q}, {P}] if partial else [{P}, {P}], [False, True], 3)
        self.td096_check(s, number, 3, full('retry-p', [p], [], Fault='trie_delete'), self.td096_reply('AF' if partial else 'A'),
                          [{P, Q}, {P}] if partial else [{P}, {P}], [False, True] if partial else [True, True], 3)

    def test_td096_x1(self):
        self.td096_atomic_sequence(1, 'src_cidr', 'fd00:96:1::/64', 'src_cidr', '10.96.2.0/24', True)

    def test_td096_x2(self):
        self.td096_atomic_sequence(2, 'src_cidr', '10.96.1.0/24', 'src_cidr', 'fd00:96:2::/64', False)

    def test_td096_x3(self):
        self.td096_atomic_sequence(3, 'dst_cidr', 'fd00:96:1::/64', 'dst_cidr', '10.96.2.0/24', True)

    def test_td096_x4(self):
        s = State()
        p, q, P, Q = self.td096_rules(4)
        self.td096_check(s, 4, 1, full('seed', [p], []), self.td096_reply('A'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 4, 2, full('replace', [q], [], Fault='trie_delete'), self.td096_reply('AF'), [{P, Q}, {P}], [False, True], 3)

    def test_td096_x5(self):
        s = State()
        p, q, P, Q = self.td096_rules(5)
        self.td096_check(s, 5, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 5, 2, self.td096_commit('swap-fault', p, q, 'trie_delete'), self.td096_reply('CF'), [{P, Q}, {P}], [False, True], 3)
        self.td096_check(s, 5, 3, self.td096_commit('retry', p, q), self.td096_reply('swap'), [{Q}, {Q}], [True, True], 4)

    def test_td096_x6(self):
        s = State()
        p, q, P, Q = self.td096_rules(6)
        self.td096_check(s, 6, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 6, 2, self.td096_commit('swap-c7', p, q, 'c-7'), self.td096_reply('C7'), [{Q}, {P}], [False, True], 3)
        self.td096_check(s, 6, 3, full('retry-p', [p], [], Fault='trie_delete'), self.td096_reply('AF'), [{Q}, {P}], [False, True], 3)

    def test_td096_x7(self):
        s = State()
        p, q, P, Q = self.td096_rules(7)
        r = dict(id='td096-x7-r', logical_id=96073, src_cidr='10.96.3.0/24', protocol='tcp', action='drop')
        self.td096_check(s, 7, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 7, 2, full('replace', [q], [], Fault='trie_delete'), self.td096_reply('AF'), [{P, Q}, {P}], [False, True], 3)
        self.td096_check(s, 7, 3, self.td096_commit('catchup-fault', r, fault='trie_delete'), self.td096_reply('CF'), [{P, Q}, {P}], [False, True], 3)

    def test_td096_x8(self):
        s = State()
        p, q, P, Q = self.td096_rules(8)
        self.td096_check(s, 8, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 8, 2, self.td096_commit('swap-rc', p, q, 'Rc'), self.td096_reply('deferred'), [{Q}, {P}], [True, False], 3)
        with self.subTest(leaf='X8.step2.references'):
            self.assertEqual(s.prefixes, {('src', '10.96.2.0/24'): 2})
            print('TD096_G1 leaf=X8.step2.references authority=PLAN-三-1-I7 result=PASS')
        self.td096_check(s, 8, 3, full('retry-p', [p], [], Fault='trie_delete'), self.td096_reply('A'), [{Q}, {P}], [False, True], 4)

    def test_td096_x9(self):
        self.td096_atomic_sequence(9, 'dst_cidr', '10.96.1.0/24', 'src_cidr', 'fd00:96:2::/64', False)

    def test_td096_x10(self):
        s = State()
        p, q, P, Q = self.td096_rules(10)
        self.td096_check(s, 10, 1, self.td096_commit('seed', p, fault='capacity_one'),
                          self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 10, 2, full('replace', [q], [], Fault='trie_delete'),
                          self.td096_reply('AF'), [{P, Q}, {P}], [False, True], 3)

    def test_td096_x11(self):
        s = State()
        p, q, P, Q = self.td096_rules(11)
        self.td096_check(s, 11, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        policy = copy.deepcopy((s.installed, s.maps, s.prefixes, s.slot, s.config_slot, s.rules_synced))
        self.td096_check(s, 11, 2, full('replace', [q], [], Fault='full_step1_delete'),
                          (500, dict(added=0, error='clear shadow blacklist: delete: injected full_step1_delete', failed=1)),
                          [{P}, {P}], [False, True], 2)
        self.assertEqual((s.installed, s.maps, s.prefixes, s.slot, s.config_slot, s.rules_synced), policy)

    def test_td096_x12(self):
        s = State()
        p, q, P, Q = self.td096_rules(12)
        r = dict(id='td096-x12-r', logical_id=96123, src_cidr='10.96.3.0/24', protocol='tcp', action='drop')
        self.td096_check(s, 12, 1, self.td096_commit('seed', p), self.td096_reply('created'), [{P}, {P}], [True, True], 2)
        self.td096_check(s, 12, 2, full('replace', [q], [], Fault='trie_delete'), self.td096_reply('AF'), [{P, Q}, {P}], [False, True], 3)
        self.td096_check(s, 12, 3, self.td096_commit('c3', r, fault='c-3'),
                          (500, dict(code='commit_failed', error='injected c-3', groups=[])), [{P, Q}, {P}], [False, True], 3)

    def test_td096_capacity_admission_controls(self):
        for fault in ('capacity_one', 'capacity_one_payment_failure'):
            with self.subTest(fault=fault):
                s = State()
                p, q, P, Q = self.td096_rules(10)
                seed_fault = fault if fault == 'capacity_one' else ''
                self.assertEqual(s.request(self.td096_commit('admitted', p, fault=seed_fault))[0], 200)
                self.assertEqual((s.prefix_copies, s.prefix_known, s.next_prefix), ([{P}, {P}], [True, True], 2))
                before = copy.deepcopy(s.__dict__)
                status, body = s.request(self.td096_commit('rejected', q, fault=fault))
                self.assertEqual((status, body['code']), (409, 'table_full'))
                self.assertEqual(s.__dict__, before)

    def td096_unknown_shadow(self, number):
        s = State()
        p, q, P, Q = self.td096_rules(number)
        r = dict(id=f'td096-x{number}-r', logical_id=96000+number*10+3,
                 src_cidr='10.96.3.0/24', protocol='tcp', action='drop')
        s.request(self.td096_commit('seed', p))
        s.request(full('partial-shadow', [q], [], Fault='trie_delete'))
        return s, P, Q, r

    def test_td096_capacity_unknown_shadow(self):
        # ruling-4 R4-3: admission must reject before repairing the unknown copy.
        s, P, Q, r = self.td096_unknown_shadow(14)
        policy = copy.deepcopy((s.installed, s.maps, s.prefixes, s.slot, s.config_slot, s.rules_synced))
        status, body = s.request(self.td096_commit('capacity-reject', r, fault='capacity_one'))
        for field, actual, expected in (
                ('status', status, 409), ('code', body.get('code'), 'table_full'),
                ('copies', s.prefix_copies, [{P, Q}, {P}]), ('known', s.prefix_known, [False, True]),
                ('next_prefix', s.next_prefix, 3),
                ('policy', (s.installed, s.maps, s.prefixes, s.slot, s.config_slot, s.rules_synced), policy)):
            with self.subTest(leaf='R4.capacity.'+field):
                self.assertEqual(actual, expected)
                print(f'TD096_G1 leaf=R4.capacity.{field} authority=ruling-4-R4-3 result=PASS')

    def test_td096_abort_unknown_shadow(self):
        # ruling-4 R4-4: CatchUp clears Q, then reservation consumes a fresh ID.
        for fault in ('c-4', 'c-5', 'c-6'):
            s, P, Q, r = self.td096_unknown_shadow(15)
            status, body = s.request(self.td096_commit('pre-apply-abort', r, fault=fault))
            for field, actual, expected in (
                    ('status', status, 500), ('code', body.get('code'), 'commit_failed'),
                    ('error', body.get('error'), 'injected '+fault), ('groups', body.get('groups'), []),
                    ('copies', s.prefix_copies, [{P}, {P}]), ('known', s.prefix_known, [False, True]),
                    ('next_prefix', s.next_prefix, 4)):
                with self.subTest(leaf=f'R4.abort.{fault}.{field}'):
                    self.assertEqual(actual, expected)
                    print(f'TD096_G1 leaf=R4.abort.{fault}.{field} authority=ruling-4-R4-4 result=PASS')

    def test_td096_atomic_preflight_preserves_known(self):
        s = State()
        p, q, P, Q = self.td096_rules(11)
        s.request(self.td096_commit('seed', p))
        cases = [('duplicate', [q, q], 'full_step1_delete', 'duplicate_id'),
                 ('capacity', [q], 'capacity_one', 'table_full'),
                 ('logical', [dict(q, ttl='64')], 'zero_logical_id', 'condition_group_invalid'),
                 ('anomaly', [dict(q, match_anomaly=16, action='rate_limit', rate_limit=1)], 'full_step1_delete', 'condition_group_invalid')]
        for name, rules, fault, code in cases:
            with self.subTest(case=name):
                branch = copy.deepcopy(s)
                status, body = branch.request(full(name, rules, [], Fault=fault))
                self.assertEqual((status, body['code']), (409, code))
                self.assertEqual(branch.__dict__, s.__dict__)

    def test_td096_i1_table_positions(self):
        old = [('src_cidr', '10.96.1.0/24'), ('dst_cidr', '10.96.2.0/24'),
               ('src_cidr', 'fd00:96:3::/64'), ('dst_cidr', 'fd00:96:4::/64')]
        new = [('src_cidr', '10.97.1.0/24'), ('dst_cidr', '10.97.2.0/24'),
               ('src_cidr', 'fd00:97:3::/64'), ('dst_cidr', 'fd00:97:4::/64')]
        for table, have, expected in (
                ('sv4', old, old), ('dv4', old[1:], [new[0], *old[1:]]),
                ('dv4-add-sv6', [old[1]], [new[0], old[1]]),
                ('sv6', old[2:], [new[0], new[1], *old[2:]]),
                ('dv6', old[3:], [new[0], new[1], new[2], old[3]])):
            for known in (False, True):
                with self.subTest(leaf='I1.'+table, known=known):
                    s = State()
                    s.prefix_copies[0] = set(have)
                    s.prefix_known[0] = known
                    self.assertFalse(s.apply_prefixes(0, set(have), set(new), 'trie_delete'))
                    self.assertEqual(s.prefix_copies, [set(expected), set()])
                    self.assertEqual(s.prefix_known, [False, False])
                    print(f'TD096_G1 leaf=I1.{table} known={known} authority=PLAN-三-1-I1-I2 result=PASS')

    def test_td096_failure_text(self):
        s = State()
        p, q, _, _ = self.td096_rules(1)
        s.request(self.td096_commit('seed', p))
        self.assertEqual(s.request(full('fail', [q], [], Fault='trie_delete'))[1]['error'], 'injected closeout trie delete')

    def test_td096_commit_pre_apply_aborts(self):
        for fault in ('c-4', 'c-5', 'c-6'):
            with self.subTest(leaf='C2.'+fault):
                s = State()
                p, q, P, _ = self.td096_rules(5)
                s.request(self.td096_commit('seed', p))
                self.assertEqual(s.request(self.td096_commit('abort', p, q, fault)),
                                 (500, dict(code='commit_failed', error='injected '+fault, groups=[])))
                self.assertEqual((s.prefix_copies, s.prefix_known, s.next_prefix, s.installed), ([{P}, {P}], [False, True], 3, [p]))
                print(f'TD096_G1 leaf=C2.{fault} authority=PLAN-二-2-C2 result=PASS')

    def test_td096_commit_old_side_failure(self):
        # Boundary fixture for C6's log-only exit: the old copy is unknown and
        # contains a stale Q. It must retain the published replacement on failure.
        s = State()
        p, q, P, Q = self.td096_rules(8)
        s.request(self.td096_commit('seed', p))
        s.prefix_copies[1].add(Q)
        s.prefix_known[1] = False
        updated = dict(p, id='td096-c6-p', logical_id=96901)
        result = s.request(step('same-prefix', 'POST', '/api/v1/rules/commit',
                               dict(groups=[dict(key=identity(p), rules=[updated])]), [], Fault='trie_delete'))
        self.assertEqual(result, (200, dict(code='committed', receipt='confirmed', groups=[dict(index=0, result='replaced')])))
        self.assertEqual((s.prefix_copies, s.prefix_known, s.next_prefix, s.installed), ([{P}, {P, Q}], [True, False], 2, [updated]))
        print('TD096_G1 leaf=C6.old-side authority=PLAN-二-2-C6 result=PASS')

    def test_protocol8_delete_failure_aborts_without_client_debt(self):
        from generate_closeout_scenarios import commit
        r = dict(id='cidr', logical_id=93, src_cidr='10.93.0.0/24', protocol='tcp', action='drop')
        state=State()
        state.request(commit('seed',[r],[]))
        before=copy.deepcopy(state.installed)
        delete=step('delete','POST','/api/v1/rules/commit',dict(groups=[dict(key=identity(r),rules=[])]),[],Fault='trie_delete')
        status,body=state.request(delete)
        self.assertEqual((status,body),(500,dict(code='commit_failed',error='injected closeout trie delete',groups=[])))
        self.assertEqual(state.installed,before)
        delete['Fault']=''
        status,body=state.request(delete)
        self.assertEqual((status,body['receipt']),(200,'confirmed'))
        self.assertNotIn('withdrawal_pending',body)
        self.assertEqual(state.installed,[])

    def test_protocol8_udp_icmp_frames_and_no_legacy_key(self):
        import struct
        from unittest.mock import patch
        from generate_closeout_scenarios import grid_scenes
        scenes=[s for s in grid_scenes() if s['Name'].startswith(('S2/udp','S2/icmp'))]
        self.assertEqual(len(scenes),4)
        with patch('reference_p3.key', side_effect=AssertionError('legacy UDP key reached')):
            for scene in scenes:
                state=State()
                for row in scene['Steps']:
                    status,body=state.request(row)
                    self.assertEqual(status,200,(scene['Name'],row['Name'],body))
                    self.assertNotIn('withdrawal_pending',body)
                    for p in row['Packets']:
                        frame=bytes.fromhex(p['Frame']); v6=':' in p['Src']; offset=54 if v6 else 34
                        self.assertEqual(len(frame),14+p['Length'])
                        if p['Proto']==17:
                            self.assertEqual(struct.unpack_from('>HHH',frame,offset),(p['Sport'],p['Dport'],8))
                        else:
                            self.assertEqual(list(frame[offset:offset+2]),[p['ICMPType'],p['ICMPCode']])
                            self.assertTrue(p['ICMPValid'])
        print('CLOSEOUT_PROTO_CONTROLS families=2 ip_versions=2 write_modes=2 frame_checks=48 legacy_key_calls=0')

    def test_startup_branches(self):
        for method in ('STARTUP_FAILURE', 'STARTUP_CLEAR_FAILURE'):
            self.assertEqual(State().request(step('startup', method, '', packets=[])), (None, {'startup_refused': True}))

    def test_whitelist_lifecycle(self):
        state = State(protocol=6)
        entry = dict(id='wl', src_ip='10.1.1.1')
        self.assertEqual(state.request(step('add', 'POST', '/api/v1/whitelist', entry))[0], 200)
        self.assertEqual(state.request(step('add', 'POST', '/api/v1/whitelist', entry))[1]['message'], 'Whitelist entry unchanged (idempotent)')
        self.assertEqual(state.whitelist_response()['count'], 1)
        state.request(step('clear', 'POST', '/api/v1/sync/whitelist', {'entries': []}))
        self.assertEqual(state.whitelist_response(), dict(count=0, entries=[]))

    def test_projection_stages(self):
        state = State()
        r = dict(rule('r', 11), action='rate_limit', rate_limit=1)
        state.request(full('load', [r]))
        winner = dict(Stage='exact', RuleID='r')
        results = [state.project_packet(packet(), winner)['verdict'] for _ in range(3)]
        self.assertEqual(results, [2, 2, 1])
        state.project_packet(packet(), dict(Stage='whitelist', RuleID='ignored'))
        state.project_packet(packet(), dict(Stage='miss', RuleID=''))
        state.request(full('drop', [rule('drop', 12)]))
        state.project_packet(packet(), dict(Stage='exact', RuleID='drop'))
        stats = state.stats_response()
        self.assertEqual([stats[k] for k in ('total_packets', 'passed_packets', 'dropped_packets', 'whitelisted_packets', 'rate_limited_packets')], [6, 4, 2, 1, 1])

    def test_logical_buckets_independent(self):
        state = State()
        a, b = dict(rule('a', 21, ttl='64'), action='rate_limit', rate_limit=1), dict(rule('b', 22, ttl='63'), action='rate_limit', rate_limit=2)
        state.request(full('both', [a, b]))
        self.assertEqual([state.take(a) for _ in range(3)], [True, True, False])
        self.assertEqual([state.take(b) for _ in range(5)], [True]*4+[False])

    def test_s7_serial_proof(self):
        data = concurrency()
        self.assertEqual(len(data['Legal']), 4)
        for row in data['Legal']:
            ids = {r['id'] for r in row['terminal']['installed']['rules']}
            self.assertFalse({'a1', 'c1'} & ids)

    def test_history_input_and_immutability(self):
        before = snapshot()
        scenes, old, rows = adapt(packet)
        self.assertEqual([sum(r[i] for r in rows.values()) for i in range(3)], [160, 354, 633])
        for scene in scenes:
            for row in scene['Steps']:
                self.assertFalse(any(k.startswith(('Expect', 'Hits')) for k in row))
        verify_unchanged(before)

    def test_fragment_domain(self):
        tiny, overflow, normal = [packet(n) for n in ('tiny_first', 'overflow_nonfirst', 'normal_nonfirst')]
        self.assertEqual((tiny['FrameLength'], tiny['Anomaly'], tiny['NonFirst']), (60, 1, False))
        self.assertEqual((overflow['Anomaly'], overflow['NonFirst']), (1, True))
        self.assertEqual((normal['Anomaly'], normal['NonFirst']), (0, True))
        self.assertGreater(8191*8+(overflow['Length']-20), 65535)

    def test_characterization_closed(self):
        cells = characterizations()
        self.assertEqual(len(cells), 6)
        self.assertEqual(len({r['TD'] for r in cells}), 4)
        self.assertTrue(all(c['Registration'] in ('registered', 'predicted') and c['Evidence'] for c in cells))

    def test_b3_enabled_contract(self):
        fixture = track_b_inputs()
        state = track_b_state(fixture)
        self.assertEqual(state.installed_response()['count'], 3)
        self.assertNotIn('startup-disabled', [r['id'] for r in state.installed])
        self.assertEqual(track_b_state(fixture, True).installed_response()['count'], 4)

    def test_protocol7_cold_full_flags_and_deleted_routes(self):
        from generate_closeout_scenarios import commit, deleted_routes
        state = State()
        health = lambda: state.request(step('health', 'GET', '/api/v1/health'))[1]
        self.assertEqual(health(), dict(status='degraded', reason='awaiting_full_sync', rules_synced=False, whitelist_synced=False))
        self.assertEqual(state.request(commit('valid', [rule('kept', 99)]))[0], 200)
        self.assertFalse(health()['rules_synced'])
        for row in deleted_routes()[0]['Steps'][1:]:
            before = copy.deepcopy(state.__dict__)
            self.assertEqual(state.request(row), (404, '404 page not found'))
            self.assertEqual(state.__dict__, before)
        state.request(full('full', [])); self.assertEqual(health()['rules_synced'], True)
        self.assertFalse(health()['whitelist_synced'])
        state.request(step('wl', 'POST', '/api/v1/sync/whitelist', {'entries': []}))
        self.assertEqual(health(), {'status': 'healthy'})
        self.assertEqual(state.installed_response()['pagination'], dict(page=1, limit=50, total=0, pages=0))
        self.assertFalse(historical_accepts('missing', 404, '404 page not found'))

    def test_example_only_shape(self):
        example = Path(__file__).resolve().parents[3]/'config.example.yaml'
        text = config_from_example(example, dict(bpf=dict(xdp_mode='generic', rate_limit_divisor=1)))
        self.assertIn('xdp_mode: "generic"', text)
        with self.assertRaises(AssertionError):
            config_from_example(example, dict(bpf=dict(unregistered=1)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
