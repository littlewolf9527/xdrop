#!/usr/bin/env python3
"""Actual extractor controls; mutations and retained evidence live in /tmp."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import re

import s2b_c_replay as replay


class CExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'], text=True).strip())
        cls.work = Path(tempfile.mkdtemp(prefix='s2b-extraction-test-', dir='/tmp'))
        cls.copy = cls.work / 'source'
        for name in ['xdrop_main.c', 'xdrop.h', 'combo_masks.h', 'headers/bpf_helpers.h']:
            p = cls.copy / 'node/bpf' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cls.root / 'node/bpf' / name, p)
        cls.original = (cls.copy / 'node/bpf/xdrop_main.c').read_bytes()
        cls.hash = replay.sha(cls.original)
        print(f'root={cls.root} source_commit=b07a004950e2f813545db540599767e2a4dc214e candidate_sha256={cls.hash} artifacts={cls.work}')

    def tearDown(self):
        (self.copy / 'node/bpf/xdrop_main.c').write_bytes(self.original)
        self.assertEqual(replay.sha((self.copy / 'node/bpf/xdrop_main.c').read_bytes()), self.hash)
        self.assertEqual(replay.sha((self.root / 'node/bpf/xdrop_main.c').read_bytes()), self.hash)
        expected_md5 = hashlib.md5(self.original).hexdigest()
        self.assertEqual(hashlib.md5((self.copy / 'node/bpf/xdrop_main.c').read_bytes()).hexdigest(), expected_md5)
        print(f'RESTORATION {self.id()} md5={expected_md5} restored_sha256={self.hash}')

    def test_sizeof_and_unknown_node_control(self):
        unit, defs, _, _ = replay.extract(self.copy, self.work / 'positive')
        nodes = [n for d in defs for n in replay.walk(d) if n['kind'] == 'UnaryExprOrTypeTraitExpr']
        # Two sizeof operands in each of the iterator bound and position guard.
        self.assertEqual(len(nodes), 8)
        self.assertEqual({n['name'] for n in nodes}, {'sizeof'})
        source = self.original.decode()
        needle = '__u16 pkt_len = attrs->pkt_len;'
        self.assertEqual(source.count(needle), 2)
        source = source.replace(needle, '(void)({ 0; });\n  ' + needle, 1)
        (self.copy / 'node/bpf/xdrop_main.c').write_text(source)
        tool = self.root / 'node/bpf/tools/s2b_c_replay.py'
        process = subprocess.run([sys.executable, str(tool), '--root', str(self.copy),
                                  '--output', str(self.work / 'unknown'), '--extract-only'],
                                 capture_output=True, text=True)
        (self.work / 'unknown.log').write_text(process.stdout + process.stderr)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('E1: unknown AST node StmtExpr', process.stderr)
        self.assertNotIn('C extraction syntax/dependency failure', process.stderr)
        row = {'node_type': 'UnaryExprOrTypeTraitExpr', 'spec': 'PLAN section three: N = sizeof(combo_order) / sizeof(combo_order[0])',
               'control': 'GNU statement expression (void)({ 0; }); in actual lookup_rule',
               'red': 'E1: unknown AST node StmtExpr', 'rc': process.returncode,
               'test': self.id(), 'restored_sha256': self.hash}
        (self.work / 'node-additions.json').write_text(json.dumps([row], indent=2) + '\n')
        print(json.dumps(row))


class InterfaceTests(unittest.TestCase):
    """Actual C fixtures; no source-identity exemption in the report consumer."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'], text=True).strip())
        cls.work = Path(tempfile.mkdtemp(prefix='s4-interface-test-', dir='/tmp'))
        cls.copy = cls.work / 'source'
        for name in ['xdrop_main.c', 'xdrop.h', 'combo_masks.h', 'headers/bpf_helpers.h']:
            target = cls.copy / 'node/bpf' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cls.root / 'node/agent/testdata/s2b-pre/node/bpf' / name, target)
        cls.path = cls.copy / 'node/bpf/xdrop_main.c'
        cls.original = cls.path.read_bytes()
        cls.original_md5 = hashlib.md5(cls.original).hexdigest()
        cls.live_md5 = hashlib.md5((cls.root / 'node/bpf/xdrop_main.c').read_bytes()).hexdigest()
        sys.path.insert(0, str(cls.root / 'node/agent/tools'))
        import check_s2b
        import s2b_cases
        cls.gate, cls.cases = check_s2b, s2b_cases
        print('S4_INTERFACE_ARTIFACTS=' + str(cls.work))

    def restore_source(self):
        self.path.write_bytes(self.original)
        self.assertEqual(hashlib.md5(self.path.read_bytes()).hexdigest(), self.original_md5)
        self.assertEqual(hashlib.md5((self.root / 'node/bpf/xdrop_main.c').read_bytes()).hexdigest(), self.live_md5)
        print('RESTORE source_md5=' + self.original_md5 + ' original_preserved=1')

    def tearDown(self):
        self.restore_source()

    def attrs_fixture(self):
        # Only the extracted callee boundary is adapted in this isolated fixture.
        # The authenticated roots are never changed to make this fixture valid.
        source = self.original.decode()
        for old, new in [
            ('__u32 len_flags', 'const struct pkt_attrs *attrs'),
            ('__u32 anom_sel', 'int rule_sel'),
            ('__u16 pkt_len = (__u16)(len_flags >> 8);', '__u16 pkt_len = attrs->pkt_len;'),
            ('__u8 tcp_flags = (__u8)(len_flags & 0xFF);', '__u8 tcp_flags = attrs->tcp_flags;'),
            ('__u8 pkt_anomaly = (__u8)(anom_sel >> 1);', '__u8 pkt_anomaly = attrs->pkt_anomaly;'),
            ('  int rule_sel = (int)(anom_sel & 1);\n', ''),
        ]:
            self.assertIn(old, source)
            source = source.replace(old, new)
        return source

    def test_registered_generations_build_and_run(self):
        rows = [self.cases.make_case(5, 24, stage, 'dual') for stage in self.cases.STAGES]
        for generation, source in [('packed', self.original.decode()), ('attrs', self.attrs_fixture())]:
            with self.subTest(generation=generation):
                self.path.write_text(source)
                try:
                    output = self.work / ('positive-' + generation)
                    binary, manifest = replay.build_replay(self.copy, output)
                    self.assertEqual(manifest['interface_generation'], generation)
                    actual = replay.run_replay(binary, [self.cases.c_input(r) for r in rows], output / 'run')
                    for row, result in zip(rows, actual):
                        self.cases.check_c(row, 's2a', result)
                    print('S4_INTERFACE generation=' + generation + ' signatures=4/4 replay=4/4 errors=0')
                finally:
                    self.restore_source()

    def test_signature_rejections(self):
        source = self.attrs_fixture()
        # Swap all four signatures, retaining the body: the P1-B counterexample.
        swapped, count = re.subn(r'int rule_sel,\s*__u64 slot', '__u64 slot, int rule_sel', source)
        self.assertEqual(count, 4)
        # Reinsert one complete packed function to exercise mixed generations.
        pattern = r'(?ms)^static[^;{}]*\blookup_rule\s*\([^;{}]*\)\s*\{'
        def function_range(text):
            hit = re.search(pattern, text)
            self.assertIsNotNone(hit)
            end, depth = hit.end(), 1
            while depth:
                depth += (text[end] == '{') - (text[end] == '}')
                end += 1
            return hit.start(), end
        a, b = function_range(source)
        x, y = function_range(self.original.decode())
        mixed = source[:a] + self.original.decode()[x:y] + source[b:]
        mutants = [
            ('last-two-swapped', swapped, 'C interface signature: lookup_rule'),
            ('parameter-name', re.sub(r'\brule_sel\b', 'selector', source), 'C interface signature: lookup_rule'),
            ('missing-const', source.replace('const struct pkt_attrs *attrs', 'struct pkt_attrs *attrs', 1), 'C interface mixed generations'),
            ('unknown-signature', source.replace('int rule_sel,', '__u32 rule_sel,', 1), 'C interface signature: lookup_rule'),
            ('mixed-generation', mixed, 'C interface mixed generations'),
        ]
        for label, mutant, red in mutants:
            with self.subTest(mutation=label):
                self.path.write_text(mutant)
                try:
                    _, defs, _, _ = replay.extract(self.copy, self.work / label)
                    with self.assertRaisesRegex(replay.ReplayError, re.escape(red)):
                        replay.select_shim(defs)
                    print('S4_INTERFACE_REJECT ' + label + ' red=' + red)
                finally:
                    self.restore_source()
        print('S4_INTERFACE_REJECTIONS=5/5 errors=0')

    def test_consumer_rejects_other_generation_shim(self):
        output = self.work / 'authenticated-report'
        before = self.root / 'node/agent/testdata/s2b-pre'
        # The historical S2b authenticated consumer stays pinned to d0bf3a7.
        # B1's changed header is intentionally rejected by the historical lock.
        after = self.work / 'historical-s2b'
        after.mkdir()
        archive = subprocess.check_output(['git', 'archive', 'd0bf3a7', 'node'], cwd=self.root)
        subprocess.run(['tar', '-x', '-C', str(after)], input=archive, check=True,
                       env=dict(os.environ, COPYFILE_DISABLE='1'))
        (after / 'internal_docs').symlink_to(self.root / 'internal_docs')
        self.gate.run(before, after, output, self.root)
        for side, root in [('before', before), ('after', after)]:
            path = output / ('c-' + side) / 'replay.c'
            original = path.read_bytes()
            original_md5 = hashlib.md5(original).hexdigest()
            unit, defs, _, _ = replay.extract(root, self.work / ('consume-extract-' + side))
            generation, _ = replay.select_shim(defs)
            wrong = replay.ATTRS_SHIM if generation == 'packed' else replay.PACKED_SHIM
            path.write_bytes(unit + wrong.encode())
            try:
                red = 'C replay build identity/RC ' + side
                with self.assertRaisesRegex(self.cases.CaseError, re.escape(red)):
                    self.gate.consume(output, before, after, self.root)
                print('S4_CONSUMER_REJECT side=' + side + ' red=' + red)
            finally:
                path.write_bytes(original)
                self.assertEqual(hashlib.md5(path.read_bytes()).hexdigest(), original_md5)
                print('RESTORE replay_md5=' + original_md5 + ' side=' + side)
            self.gate.consume(output, before, after, self.root)
        print('S4_CONSUMER_WRONG_SHIM=2/2 errors=0')


class TD035SemanticGenerationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[3]
        self.tmp = tempfile.TemporaryDirectory(prefix='td035-generation-')
        self.addCleanup(self.tmp.cleanup)
        self.copy = Path(self.tmp.name) / 'source'
        for name in ('xdrop_main.c', 'xdrop.h', 'combo_masks.h', 'headers/bpf_helpers.h'):
            p = self.copy / 'node/bpf' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root / 'node/bpf' / name, p)

    def test_live_b1l4(self):
        record = replay.check_source(self.copy, Path(self.tmp.name) / 'check')
        self.assertEqual(record['semantic_generation'], 'b1cut54')
        _, defs, _, _ = replay.extract(self.copy, Path(self.tmp.name) / 'extract')
        self.assertEqual(replay.interface_generation(defs), 'b1cut54')
        self.assertEqual(replay.select_shim(defs), ('b1cut54', replay.CUT54_SHIM))
        replay.build_replay(self.copy, Path(self.tmp.name) / 'replay')

    def test_mixed_helper_and_predicates_rejected(self):
        p = self.copy / 'node/bpf/xdrop_main.c'
        source = p.read_text()
        old = subprocess.check_output(['git', 'show', '003e473:node/bpf/xdrop_main.c'], cwd=self.root, text=True)
        pattern = r'(?ms)^static __attribute__\(\(noinline\)\) int tcp_flags_matches\(.*?^}'
        old_helper, new_helper = re.search(pattern, old)[0], re.search(pattern, source)[0]
        mutants = {
            'old-helper-new-predicates': source.replace(new_helper, old_helper),
            'new-helper-old-predicates': source.replace(
                'tcp_flags_matches(rule, key->protocol, tcp_flags, attrs->l4_valid)',
                'tcp_flags_matches(rule, key->protocol, tcp_flags)'),
        }
        for name, mutant in mutants.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutant, source)
                p.write_text(mutant)
                with self.assertRaisesRegex(replay.ReplayError, 'C semantic mixed generations'):
                    replay.check_source(self.copy, Path(self.tmp.name) / name)
        p.write_text(source)

    def test_d0bf3a7_with_live_tool(self):
        for name in ('xdrop_main.c', 'xdrop.h', 'combo_masks.h', 'headers/bpf_helpers.h'):
            raw = subprocess.check_output(['git', 'show', 'd0bf3a7:node/bpf/' + name], cwd=self.root)
            (self.copy / 'node/bpf' / name).write_bytes(raw)
        replay.check_source(self.copy, Path(self.tmp.name) / 'historical')
        _, defs, _, _ = replay.extract(self.copy, Path(self.tmp.name) / 'old-extract')
        self.assertEqual(replay.interface_generation(defs), 'attrs')
        self.assertEqual(replay.select_shim(defs), ('attrs', replay.ATTRS_SHIM))


if __name__ == '__main__':
    unittest.main(verbosity=2)
