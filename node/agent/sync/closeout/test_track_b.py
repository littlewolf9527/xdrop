#!/usr/bin/env python3
"""Offline controls for real-process wiring assertions; no process or socket use."""
import contextlib
import copy
import io
import tempfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path
import track_b
from compare_closeout import COUNTERS

REAL_WRITE = track_b.write


class WiringControls(unittest.TestCase):
    def test_example_shape_rejects_unknown_field(self):
        example = Path(__file__).resolve().parents[3]/'config.example.yaml'
        text = track_b.config_from_example(example, {'bpf': {'rate_limit_divisor': 1}})
        self.assertIn('rate_limit_divisor: 1', text)
        with self.assertRaises(AssertionError):
            track_b.config_from_example(example, {'bpf': {'unknown_setting': 1}})

    def setUp(self):
        writer = patch('track_b.write')
        writer.start()
        self.addCleanup(writer.stop)

    def test_default_agent_mode_is_require(self):
        import inspect
        self.assertEqual(inspect.signature(track_b.Supervisor.start_agent).parameters['pinning'].default, 'require')

    def b5_fixture(self, before_tokens=0, after_present=False, expected_present=False, reachable=True):
        sup = object.__new__(track_b.Supervisor)
        sup.s = Path('/unwritten-control')
        sup.fixture = {'packets': [{}]*3}
        sup.expected = {'bucket_after_restart': {'present': expected_present}}
        cold = dict(status='degraded', reason='awaiting_full_sync', rules_synced=False, whitelist_synced=False)
        events = []
        sup.character = lambda _: {'initial': cold}
        sup.stop_agent = lambda: events.append('stop')
        sup.start_agent = lambda **kw: events.append('start') or {'api_reachable':reachable}
        sup.push_fixture = lambda: events.append('push')
        sup.send = lambda *_: events.append('send')
        def snapshot(label):
            events.append(label)
            return dict(present=True, slots=[dict(cpu=0,tokens=before_tokens,last_update_present=True)]) if label=='before-restart' else dict(present=after_present)
        sup.snapshot = snapshot
        health = iter((cold, dict(status='healthy')))
        sup.get = lambda _: next(health)
        sup.installed = lambda name: events.append(name)
        return sup, events

    def test_b5_require_and_bucket_preconditions(self):
        for tokens, ready, message in ((1,True,'not-executed'), (0,False,'B-5/require')):
            sup, events = self.b5_fixture(before_tokens=tokens,reachable=ready)
            with self.subTest(tokens=tokens, ready=ready), patch('builtins.print'):
                with self.assertRaisesRegex(AssertionError,message): sup.b5()
                self.assertNotIn('after-restart', events)

    def test_b5_node_and_oracle_mutants_red_at_bucket(self):
        for present, expected in ((True,False),(False,True)):
            sup, events = self.b5_fixture(after_present=present,expected_present=expected)
            with self.subTest(present=present), patch('builtins.print'):
                with self.assertRaisesRegex(AssertionError,'CLOSEOUT_WITNESS B-5/bucket'): sup.b5()
                self.assertEqual(events[-1], 'after-restart')
                self.assertEqual(events.count('push'),1)
        print('CLOSEOUT_B5_BUCKET_CONTROLS node_mutant_red=1 oracle_mutant_red=1 named_bucket=2')

    def test_b5_bucket_precedes_probe_and_push_record_survives(self):
        sup, events = self.b5_fixture()
        with tempfile.TemporaryDirectory() as temp, patch('track_b.write',REAL_WRITE), patch('builtins.print'):
            sup.s = Path(temp)
            sup.b5()
            self.assertEqual(events, ['stop','start','push','send','before-restart','stop','start','after-restart','push','B-5/installed'])
            self.assertTrue(sup.b5_checked)
            record=track_b.read(sup.s/track_b.B5_RECORD)
            self.assertTrue(record['consumed_on_one_cpu'])
            self.assertEqual(record['after'], {'present':False})
            self.assertEqual(track_b.read(sup.s/'B-5_bucket.json')['differences'], [])
        print('CLOSEOUT_B5_ORDER consumed=1 read_before_probe_push=1 record_preserved=1')

    def b6_fixture(self, swapped=False, extra_cpu=False, nonzero=False):
        before = dict(zip(COUNTERS, (9, 3, 6, 1, 2))) if nonzero else dict.fromkeys(COUNTERS, 0)
        expected = dict(zip(COUNTERS, (6, 2, 4, 1, 1)))
        after = {k: before[k]+expected[k] for k in COUNTERS}
        cpu_before = {'per_cpu': [dict(before, cpu=3), dict.fromkeys(COUNTERS, 0) | {'cpu': 4}]}
        cpu_after = {'per_cpu': [dict(after, cpu=3), dict.fromkeys(COUNTERS, 0) | {'cpu': 4}]}
        if extra_cpu:
            cpu_after['per_cpu'][0]['total_packets'] -= 1
            cpu_after['per_cpu'][1]['total_packets'] += 1
        if swapped:
            after['dropped_packets'], after['passed_packets'] = 4, 2
        sup = object.__new__(track_b.Supervisor)
        sup.a = types.SimpleNamespace(cpu=3)
        sup.fixture = {'packets': [{}]*6, 'no_refill_ns': 1000}
        sup.expected = {'delta': expected}
        sup.s = Path('/unwritten-control')
        sup.stop_agent = sup.start_agent = sup.push_fixture = lambda: None
        sup.send = lambda *_: None
        values = iter((before, cpu_before, after, cpu_after))
        sup.get = lambda *_: next(values)
        seen = []
        def equal(name, actual, expected):
            seen.append(name)
            if actual != expected:
                raise AssertionError('CLOSEOUT_WITNESS '+name)
        sup.equal = equal
        return sup, seen

    def b1_fixture(self, missing=False):
        sup = object.__new__(track_b.Supervisor)
        sup.a = types.SimpleNamespace(routes=str(Path(__file__).with_name('routes.json')))
        calls, keys, logical = [], set(), set()
        def request(method, path, body=None, key=True):
            calls.append((method, path, key))
            if missing and path == '/api/v1/sync/whitelist' and method == 'POST':
                return 404, {}
            if path in ('/', '/api/v1/health'):
                self.assertFalse(key)
                return 200, {'sync_protocol': 11}
            if not key:
                return 401, {}
            from generate_closeout_scenarios import deleted_routes
            if any((method, path) == (r['Method'], r['Path']) for r in deleted_routes()[0]['Steps'][1:]):
                return 404, '404 page not found'
            if method == 'POST' and body and body.get('id', '').startswith('route-probe-'):
                if path.endswith('/rules'):
                    self.assertNotIn(body['src_ip'], keys)
                    self.assertNotIn(body['logical_id'], logical)
                    keys.add(body['src_ip'])
                    logical.add(body['logical_id'])
            return 200, {}
        sup.request = request
        sup.get = lambda p: {'count': 0, 'rules': []} if p.endswith('/rules') else {'count': 0, 'entries': []}
        def equal(name, actual, expected):
            if actual != expected:
                raise AssertionError('CLOSEOUT_WITNESS '+name)
        sup.equal = equal
        return sup, calls

    def test_b1_public_auth_and_distinct_seed_controls(self):
        sup, calls = self.b1_fixture()
        with patch('builtins.print'):
            sup.b1()
        self.assertEqual(sum(not key for _, path, key in calls if path not in ('/', '/api/v1/health')), 8)

    def test_b1_missing_route_reaches_route_witness(self):
        sup, calls = self.b1_fixture(missing=True)
        with self.assertRaisesRegex(AssertionError, 'B-1/route/POST/api/v1/sync/whitelist'):
            sup.b1()
        self.assertEqual(calls[-1], ('POST', '/api/v1/sync/whitelist', True))

    def test_b6_counter_mutant_reaches_named_assertion(self):
        sup, seen = self.b6_fixture(swapped=True)
        with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-6/counts'):
            sup.b6()
        self.assertEqual(seen, ['B-6/counts'])

    def test_b6_single_cpu_is_required(self):
        sup, seen = self.b6_fixture(extra_cpu=True)
        with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-6/one-cpu'):
            sup.b6()
        self.assertEqual(seen, ['B-6/counts', 'B-6/one-cpu'])

    def test_b6_positive_counter_and_cpu_controls(self):
        sup, seen = self.b6_fixture()
        with patch('builtins.print'):
            sup.b6()
        self.assertEqual(seen, ['B-6/counts', 'B-6/one-cpu', 'B-6/cpu-delta'])


    def test_b6_nonzero_baseline_exact_delta(self):
        sup, seen = self.b6_fixture(nonzero=True)
        with patch('builtins.print'):
            sup.b6()
        self.assertEqual(seen, ['B-6/counts', 'B-6/one-cpu', 'B-6/cpu-delta'])

    def b7_fixture(self, bad_field=None, late_field=None, cpu_shift=None, nonzero=True):
        sup = object.__new__(track_b.Supervisor)
        sup.a = types.SimpleNamespace(cpu=3)
        sup.s = Path('/unwritten-control')
        sup.expected = {'xdp_info': {'mode': 'traditional'}}
        first = dict(zip(COUNTERS, (6, 2, 4, 1, 1)))
        last = dict(zip(COUNTERS, (7, 2, 5, 1, 1)))
        extras = dict(ipv6_deep_chain_dropped=0, mapped_v6_dropped=0, cond_row_missing=0, tailcall_fail=0, rules_count=0,
                      whitelist_count=0, system={}, agent_state={})
        installed, whitelist = dict(count=0, rules=[]), dict(count=0, entries=[])
        sup.data, sup.expected_a = {'Scenes': []}, {}
        for i in range(3):
            name = 'S1/long-'+str(i)
            rows = [dict(Name='push', Method='POST', Path='/api/v1/sync/atomic', Body={}, Packets=[{}]*6, RateLimits={}),
                    dict(Name='stats', Method='GET', Path='/api/v1/stats', Body=None, Packets=[{}], RateLimits={})]
            sup.data['Scenes'].append(dict(Name=name, Family='S1', TrackB=True, Steps=rows))
            for row in rows:
                sup.expected_a[name+'/'+row['Name']] = dict(status=200,
                    body=dict(first, **extras) if row['Name']=='stats' else {},
                    stats=dict(last, **extras), installed=installed, installed_after=installed, whitelist=whitelist)
        current = [dict(zip(COUNTERS, values)) for values in ((9, 3, 6, 1, 2), (7, 2, 5, 1, 1))]
        if not nonzero:
            current = [dict.fromkeys(COUNTERS, 0) for _ in current]
        events, sends = [], [0]
        def start():
            events.append('start')
            sends[0] = 0
        sup.start_agent = start
        sup.stop_agent = lambda: events.append('stop')
        def cpu_rows():
            rows = [dict(r, cpu=i+3) for i, r in enumerate(current)]
            if sends[0] and bad_field:
                rows[0][bad_field] += 1
            if sends[0] == 2 and late_field:
                rows[0][late_field] += 1
            if sends[0] and cpu_shift:
                rows[0][cpu_shift] -= 1
                rows[1][cpu_shift] += 1
            return rows
        def get(path):
            events.append(path)
            if path == '/api/v1/rules': return copy.deepcopy(installed)
            if path == '/api/v1/whitelist': return copy.deepcopy(whitelist)
            rows = cpu_rows()
            if path == '/api/v1/stats/cpu': return {'per_cpu': rows}
            self.assertEqual(path, '/api/v1/stats')
            return dict({k: sum(r[k] for r in rows) for k in COUNTERS}, **dict(extras,
                        cond_row_missing=4 if nonzero else 0, xdp_info=sup.expected['xdp_info']))
        sup.get = get
        sup.request = lambda method, path, body: (200, get(path) if method=='GET' else {})
        def send(packets):
            events.append('send')
            delta = first if len(packets)==6 else {k: last[k]-first[k] for k in COUNTERS}
            for k in COUNTERS: current[0][k] += delta[k]
            sends[0] += 1
        sup.send = send
        return sup, events

    def test_b7_nonzero_baselines_exact_delta_and_evidence(self):
        sup, events = self.b7_fixture()
        expected = copy.deepcopy(sup.expected_a)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp, patch('track_b.write', REAL_WRITE), contextlib.redirect_stdout(output):
            sup.s = Path(temp)
            sup.b7()
            records = sorted(sup.s.glob('*-stats-baseline.json'))
            self.assertEqual(len(records), 3)
            self.assertEqual([track_b.read(p)['stats']['total_packets'] for p in records], [16, 23, 30])
            self.assertTrue(all('cpu' in track_b.read(p) for p in records))
            self.assertEqual(len(list(sup.s.glob('*-stats-after.json'))), 3)
        for i, event in enumerate(events):
            if event == 'start': self.assertEqual(events[i+1:i+3], ['/api/v1/stats', '/api/v1/stats/cpu'])
        self.assertEqual(sup.expected_a, expected)
        self.assertEqual(output.getvalue().count('CLOSEOUT_B7_STATS_BASELINE scenes=3 first_nonzero=1'), 1)
        print('CLOSEOUT_B7_BASELINE_CONTROL nonzero_green=1 evidence_scenes=3 before_first_packet=1 fields=5')

    def test_b7_each_counter_off_by_one_is_red(self):
        for field in COUNTERS:
            with self.subTest(field=field), patch('builtins.print'):
                sup, _ = self.b7_fixture(bad_field=field)
                with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-7/S1/long-0/stats/cpu_delta'):
                    sup.b7()
        print('CLOSEOUT_B7_DELTA_CONTROLS off_by_one_red=5')

    def test_b7_last_packets_are_in_scene_delta(self):
        for field in COUNTERS:
            with self.subTest(field=field), patch('builtins.print'):
                sup, _ = self.b7_fixture(late_field=field)
                with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-7/S1/long-0/stats_after'):
                    sup.b7()
        print('CLOSEOUT_B7_END_CONTROLS last_packet_delta_red=5')

    def test_b7_per_cpu_each_counter_is_exact(self):
        for field in COUNTERS:
            with self.subTest(field=field), patch('builtins.print'):
                sup, _ = self.b7_fixture(cpu_shift=field)
                with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-7/S1/long-0/stats/cpu_delta'):
                    sup.b7()
        print('CLOSEOUT_B7_CPU_CONTROLS aggregate_unchanged_cpu_red=5')

    def test_b7_old_absolute_comparison_is_red(self):
        sup, _ = self.b7_fixture()
        with patch('track_b.stats_delta', lambda stats, before: stats), patch('builtins.print'):
            with self.assertRaisesRegex(AssertionError, 'CLOSEOUT_WITNESS B-7/S1/long-0/stats/reply'):
                sup.b7()
        print('CLOSEOUT_B7_OLD_CONTROL nonzero_absolute_red=1')

    def test_b7_zero_baseline_is_record_only(self):
        sup, _ = self.b7_fixture(nonzero=False)
        output = io.StringIO()
        with contextlib.redirect_stdout(output): sup.b7()
        self.assertEqual(output.getvalue().count('CLOSEOUT_B7_STATS_BASELINE scenes=3 first_nonzero=0'), 1)



if __name__ == '__main__':
    unittest.main(verbosity=2)
