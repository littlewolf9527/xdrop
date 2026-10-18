#!/usr/bin/env python3
"""Register the complete 5-4 shape before switching the production C source."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import s2b_c_replay as replay
import extract_combo_masks as masks

ROOT = Path(__file__).resolve().parents[3]
FILES = ('xdrop_main.c', 'xdrop.h', 'combo_masks.h', 'headers/bpf_helpers.h')


def remove_function(source, name):
    hit = re.search(r'(?m)^(?:static[^;{}]*|int )\b' + name + r'\s*\([^;{}]*\)\s*\{', source)
    if hit is None:
        raise AssertionError('fixture function missing: ' + name)
    end, depth = hit.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[:hit.start()] + source[end:]


def future_source(source):
    source = '#define B1_LOOKUP_GENERATION 54\n' + source
    for name in ('lookup_rule_anomaly', 'lookup_cidr_rule_anomaly', 'xdp_anomaly_verify'):
        source = remove_function(source, name)
    anchor = '    build_cidr_rule_key(matched_key, key, b);'
    assert source.count(anchor) == 1
    source = source.replace(anchor, '''    if (((combo_field_mask[b] & CM_SRC_IP) && key->src_id == 0) ||
        ((combo_field_mask[b] & CM_DST_IP) && key->dst_id == 0))
      continue;

''' + anchor)
    anchor = '      if (cv && cond_match(cv, attrs) >= 0)'
    assert source.count(anchor) == 2
    return source.replace(anchor, '''      if (!cv) {
        __u32 zero = 0;
        __u64 *missing = bpf_map_lookup_elem(&cond_row_missing, &zero);
        if (missing)
          (*missing)++;
      }
''' + anchor)


class Cut54Generation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cut54-generation-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'source'
        for name in FILES:
            p = self.root/'node/bpf'/name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(subprocess.check_output(['git', 'show', '923ee82:node/bpf/'+name], cwd=ROOT))
        self.path = self.root/'node/bpf/xdrop_main.c'
        self.old = self.path.read_text()
        self.new = future_source(self.old)

    def check(self, source, label):
        self.path.write_text(source)
        return replay.check_source(self.root, Path(self.tmp.name)/label)

    def test_old_and_new_complete_generations(self):
        for label, source, semantic, count in [('old', self.old, 'b1l4', 8), ('new', self.new, 'b1cut54', 6)]:
            with self.subTest(generation=label):
                record = self.check(source, label)
                self.assertEqual(record['semantic_generation'], semantic)
                self.assertEqual(len(record['functions']), count)
                masks.verify_shared_source(source.splitlines())
                replay.build_replay(self.root, Path(self.tmp.name)/(label+'-run'))
        print('CUT54_GENERATION old_functions=8 new_functions=6 old_aligned=7 new_aligned=4')

    def test_historical_missing_function_stays_red(self):
        for name in replay.NAMES[4:]:
            with self.subTest(function=name):
                with self.assertRaisesRegex(replay.ReplayError, 'E1: '+name+' definitions=0'):
                    self.check(remove_function(self.old, name), 'missing-'+name)
        print('CUT54_HISTORICAL_MISSING reds=4')

    def test_new_generation_guards(self):
        trials = [
            ('src', self.new.replace('CM_SRC_IP) && key->src_id == 0', 'CM_SRC_IP) && key->src_id == 1'), 'C TD-084 zero-ID dominating guard'),
            ('dst', self.new.replace('CM_DST_IP) && key->dst_id == 0', 'CM_DST_IP) && key->dst_id == 1'), 'C TD-084 zero-ID dominating guard'),
            ('missing-counter', self.new.replace('(*missing)++;', '(*missing) += 0;', 1), 'C B1 condition lookup/output/fallback contract'),
            ('wrong-diagnostic-branch', self.new.replace('if (!cv)', 'if (cv)', 1), 'C B1 condition lookup/output/fallback contract'),
        ]
        for label, mutant, error in trials:
            with self.subTest(mutation=label):
                self.assertNotEqual(mutant, self.new)
                with self.assertRaisesRegex(replay.ReplayError, error):
                    self.check(mutant, label)
        print('CUT54_GENERATION_MUTATIONS reds=4 target_branches=4')

    def test_generator_projection(self):
        for name in ('extract_combo_masks.py', 's2b_c_replay.py', 'combo_masks_pre_m1.json'):
            p = self.root/'node/bpf/tools'/name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/'node/bpf/tools'/name, p)
        for label, source in [('old', self.old), ('new', self.new)]:
            self.path.write_text(source)
            p = subprocess.run(['python3', str(self.root/'node/bpf/tools/extract_combo_masks.py'), '--emit-c'], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            self.assertEqual(p.stdout, (self.root/'node/bpf/combo_masks.h').read_bytes(), label)
        self.path.write_text(remove_function(self.old, 'lookup_rule_anomaly'))
        p = subprocess.run(['python3', str(self.root/'node/bpf/tools/extract_combo_masks.py'), '--emit-c'], capture_output=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('当前查表函数集', p.stderr.decode())
        print('CUT54_GENERATOR old=pass new=pass historical_missing=red masks_byte_equal=2')


if __name__ == '__main__':
    unittest.main(verbosity=2)
