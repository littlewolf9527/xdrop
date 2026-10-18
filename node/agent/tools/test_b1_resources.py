#!/usr/bin/env python3
"""Synthetic B1 judge controls. These are not kernel acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import check_s2b_facts as facts

ROOT = Path(__file__).resolve().parents[3]


class B1Resources(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='b1-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.records = {}
        for side in ('before', 'after'):
            folder = self.base/side
            folder.mkdir()
            record = {'source_commit': facts.B1_BASE_COMMIT,
                      'context': {'kernel': 'synthetic-kernel', 'clang': 'synthetic-clang',
                                  'arch': 'synthetic-arch', 'rc': 0}, 'inputs': {}, 'artifacts': {}}
            for name in facts.B1_INPUTS:
                data = (__import__('subprocess').check_output(['git', 'show', facts.B1_BASE_COMMIT+':'+name], cwd=ROOT)
                        if side == 'before' else (ROOT/name).read_bytes())
                dest = folder/'inputs'/name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                record['inputs'][name] = self.sha(data)
            for name in facts.B1_ELFS | {'m0probe'}:
                data = ('SYNTHETIC '+name).encode()
                (folder/name).write_bytes(data)
                record['artifacts'][name] = self.sha(data)
            record['context']['probe_sha256'] = record['artifacts']['m0probe']
            build = ''.join('clang -O2 -g -Wall -target bpf -D__BPF__ -I./headers  -c '+n+'.c -o '+n+'.elf\n' for n in ('xdrop_main', 'xdrop_gate'))
            self.records[side] = record
            self.write(side, 'build.log', build)
            log = ''
            for name, entries in [('xdrop_main.elf', ['xdp_firewall_main', 'xdp_anomaly_verify']), ('xdrop_gate.elf', ['xdp_whitelist_gate'])]:
                log += f'ELF: {name}\nELF sha256: {record["artifacts"][name]}  ({(folder/name).stat().st_size} bytes, 哈希与加载用同一份字节)\n'
                for entry in entries:
                    log += f'──── 入口 {entry} ────\n✅ VerifiedInstructions = 100000   (synthetic)\nstack depth 320+40+40\nprocessed 100000 insns (limit 1000000)\n'
            log += '本轮结果【SYNTHETIC】: ✅ 全部程序通过 verifier\n'
            self.write(side, 'probe.log', log)
        self.log = (self.base/'after/probe.log').read_text()
        self.save()
        self.before_sha = self.sha((self.base/'before/record.json').read_bytes())

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def write(self, side, name, text):
        data = text.encode()
        (self.base/side/name).write_bytes(data)
        self.records[side]['artifacts'][name] = self.sha(data)

    def save(self):
        for side, record in self.records.items():
            (self.base/side/'record.json').write_text(json.dumps(record))

    def judge(self, expected=None, retired=None, knife=1):
        self.save()
        return facts.b1_resources(self.base/'before/record.json', self.base/'after/record.json', self.before_sha,
                                  sorted(facts.B1_ENTRIES) if expected is None else expected,
                                  [] if retired is None else retired, knife, ROOT)

    def test_green_baseline(self):
        self.assertEqual(len(self.judge()['entries']), 3)

    def test_red_before_as_after(self):
        self.assertNotEqual(self.records['before']['inputs'], self.records['after']['inputs'])
        with self.assertRaisesRegex(ValueError, 'B1 after source drift:'):
            facts.b1_resources(self.base/'before/record.json', self.base/'before/record.json',
                               self.before_sha, sorted(facts.B1_ENTRIES), [], 1, ROOT)

    def test_red_live_input_drift(self):
        tree = self.base/'tree'
        shutil.copytree(self.base/'after/inputs', tree)

        def judge():
            # Knife two skips the Git anchor check; the after-tree binding is
            # required on every knife and needs no synthetic Git history.
            return facts.b1_resources(self.base/'before/record.json', self.base/'after/record.json',
                                      self.before_sha, sorted(facts.B1_ENTRIES), [], 2, tree)

        self.assertEqual(judge()['verdict'], 'PASS')
        for name in sorted(facts.B1_INPUTS):
            with self.subTest(input=name):
                path = tree/name
                original = path.read_bytes()
                try:
                    path.write_bytes(original+b'\nSOURCE DRIFT\n')
                    with self.assertRaisesRegex(ValueError, 'B1 after source drift:'):
                        judge()
                finally:
                    path.write_bytes(original)
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(judge()['verdict'], 'PASS')

    def test_green_removed_delta_limits(self):
        # All obsolete quotas exceeded, including conservative sum; only the
        # kernel can judge the real call chain. This fixture is NOT a load.
        self.write('after', 'probe.log', self.log.replace('= 100000', '= 500000').replace('processed 100000 ', 'processed 500000 ').replace('320+40+40', '400+96+96'))
        rows = self.judge()['entries']
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r['budget_percent'] == 50 for r in rows))

    def test_red_log_contracts(self):
        cases = {
            'budget': (self.log.replace('= 100000', '= 500001').replace('processed 100000 ', 'processed 500001 '), 'budget ceiling'),
            'zero': (self.log.replace('100000', '0', 1), 'instructions missing/duplicate'),
            'missing_entry': (self.log.replace('──── 入口 xdp_anomaly_verify ────', 'absent'), 'entry identities'),
            'duplicate_entry': (self.log.replace('──── 入口 xdp_firewall_main ────', '──── 入口 xdp_anomaly_verify ────'), 'entry identities'),
            'missing_vi': (self.log.replace('✅ VerifiedInstructions', 'absent', 1), 'instructions missing/duplicate'),
            'duplicate_vi': (self.log.replace('stack depth', '✅ VerifiedInstructions = 123 (synthetic)\nstack depth', 1), 'instructions missing/duplicate'),
            'missing_frames': (self.log.replace('stack depth', 'absent', 1), 'frames missing/duplicate'),
            'duplicate_frames': (self.log.replace('stack depth', 'stack depth 1\nstack depth', 1), 'frames missing/duplicate'),
            'missing_raw': (self.log.replace('processed 100000 insns', 'absent', 1), 'raw verifier reading'),
            'failed_load': (self.log+'🔴\n', 'successful load summary'),
            'missing_summary': (self.log.replace('✅ 全部程序通过 verifier', 'absent'), 'successful load summary'),
            'loaded_hash': (self.log.replace(self.records['after']['artifacts']['xdrop_main.elf'], '0'*64), 'loaded ELF identity'),
            'loaded_size': (self.log.replace('24 bytes', '25 bytes'), 'loaded ELF identity'),
            'missing_elf': (self.log.replace('ELF: xdrop_gate.elf', 'absent'), 'loaded ELF set'),
        }
        # Do not silently count a no-op mutation.
        for name, (log, error) in cases.items():
            with self.subTest(name=name):
                self.assertNotEqual(log, self.log)
                self.write('after', 'probe.log', log)
                with self.assertRaisesRegex(ValueError, error):
                    self.judge()
        self.write('after', 'probe.log', self.log)
        self.assertEqual(self.judge()['verdict'], 'PASS')

    def test_red_environment(self):
        for field in ('kernel', 'clang', 'arch', 'probe_sha256', 'rc'):
            with self.subTest(field=field):
                original = copy.deepcopy(self.records['after'])
                self.records['after']['context'][field] = 1 if field == 'rc' else 'different'
                with self.assertRaisesRegex(ValueError, 'environment/RC|probe identity|incomparable'):
                    self.judge()
                self.records['after'] = original
        # Rehash a changed probe too: identity consistency is not comparability.
        self.write('after', 'm0probe', 'different probe')
        self.records['after']['context']['probe_sha256'] = self.records['after']['artifacts']['m0probe']
        with self.assertRaisesRegex(ValueError, 'incomparable'):
            self.judge()

    def test_red_evidence(self):
        for key in sorted(self.records['after']['artifacts']):
            with self.subTest(missing=key):
                digest = self.records['after']['artifacts'].pop(key)
                with self.assertRaisesRegex(ValueError, 'artifact set'):
                    self.judge()
                self.records['after']['artifacts'][key] = digest
        self.write('after', 'build.log', 'make -n\n')
        with self.assertRaisesRegex(ValueError, 'expanded compile command'):
            self.judge()

    def test_red_hash_and_before_pin(self):
        (self.base/'after/probe.log').write_text(self.log+'drift')
        with self.assertRaisesRegex(ValueError, 'evidence hash'):
            self.judge()
        self.write('after', 'probe.log', self.log)
        self.before_sha = '0'*64
        with self.assertRaisesRegex(ValueError, 'registered before identity'):
            self.judge()

    def test_red_explicit_entries(self):
        for expected, retired, knife in [([], [], 1), (['xdp_firewall_main', 'xdp_whitelist_gate'], ['xdp_anomaly_verify'], 1),
                                          (list(facts.B1_ENTRIES)*2, [], 1), (list(facts.B1_ENTRIES), [], 5)]:
            with self.subTest(expected=expected, retired=retired, knife=knife):
                with self.assertRaisesRegex(ValueError, 'explicit entry contract'):
                    self.judge(expected, retired, knife)

    def test_green_only_knife_five_retires_anomaly(self):
        fragment = '──── 入口 xdp_anomaly_verify ────\n✅ VerifiedInstructions = 100000   (synthetic)\nstack depth 320+40+40\nprocessed 100000 insns (limit 1000000)\n'
        self.write('after', 'probe.log', self.log.replace(fragment, ''))
        self.assertEqual(len(self.judge(['xdp_firewall_main', 'xdp_whitelist_gate'], ['xdp_anomaly_verify'], 5)['entries']), 2)

    def test_red_first_anchor(self):
        self.records['before']['source_commit'] = '0'*40
        self.save()
        self.before_sha = self.sha((self.base/'before/record.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'first anchor commit'):
            self.judge()
        self.records['before']['source_commit'] = facts.B1_BASE_COMMIT
        name = 'node/bpf/xdrop_main.c'
        (self.base/'before/inputs'/name).write_bytes(b'different source')
        self.records['before']['inputs'][name] = self.sha(b'different source')
        self.save()
        self.before_sha = self.sha((self.base/'before/record.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'first anchor source'):
            self.judge()

    def test_red_missing_input_or_file(self):
        name = 'node/bpf/xdrop_main.c'
        digest = self.records['after']['inputs'].pop(name)
        with self.assertRaisesRegex(ValueError, 'compile input set'):
            self.judge()
        self.records['after']['inputs'][name] = digest
        (self.base/'after/probe.log').unlink()
        with self.assertRaises(FileNotFoundError):
            self.judge()

    def test_red_duplicate_json(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            facts.b1_json('{"rc":0,"rc":1}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
