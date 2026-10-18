"""Old/new measurement boundaries and positive/negative host controls."""
import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
import unittest

import b1_cfg_cost as cost
import b1_condition_probe as probe
from test_b1_cfg_cost import fixture
from test_cut54_source_generation import Cut54Generation


class Cut54Measurements(unittest.TestCase):
    def test_cfg_both_entry_sets_require_main(self):
        for anomaly in (True, False):
            with self.subTest(anomaly=anomaly), tempfile.TemporaryDirectory(prefix='cut54-cost-') as tmp:
                args=fixture(Path(tmp), hit_entry=True, include_anomaly=anomaly)
                result=cost.measure(*args)
                self.assertEqual(result['paths']['condition_hit']['instructions'],27)
                self.assertEqual(result['tool_sha256'],hashlib.sha256(Path(cost.__file__).read_bytes()).hexdigest())
                self.assertEqual('xdp_anomaly_verify' in result['functions'],anomaly)
                source=args[1]
                source.write_text(source.read_text().replace('int has_conditions =','int wrong_anchor ='))
                with self.assertRaisesRegex(AssertionError,'main hit classification missing'):
                    cost.measure(*args)
        print('CUT54_CFG old=pass new=pass missing_MI_red=2 tool_sha_bound=2')

    def test_actual_source_hit_anchor_controls(self):
        import subprocess
        root=Path(__file__).resolve().parents[3]
        sources=[('live',(root/'node/bpf/xdrop_main.c').read_text())]
        for revision in ('d0bf3a7','7e405a7','923ee82'):
            sources.append((revision,subprocess.check_output(['git','show',revision+':node/bpf/xdrop_main.c'],cwd=root,text=True)))
        for label, text in sources:
            hits, entries=cost.source_hit_anchors(text)
            self.assertTrue(hits)
            if entries:
                self.assertEqual(len(entries),2)
                for spelling in ('int has_conditions = rule->pad2[0] & RULE_HAS_CONDITIONS;',
                                 'int has_conditions = cidr_rule->pad2[0] & RULE_HAS_CONDITIONS;',
                                 'counter->match++;'):
                    with self.subTest(tree=label,anchor=spelling):
                        for mutant in (text.replace(spelling,'/* missing hit anchor */'), text+'\n'+spelling+'\n'):
                            with self.assertRaisesRegex(AssertionError,'anchor count'):
                                cost.source_hit_anchors(mutant)
            else:
                for mutant in (text.replace('rule->match_count++;','/* missing */',1),text+'\nrule->match_count++;\n'):
                    with self.assertRaisesRegex(AssertionError,'anchor count'):
                        cost.source_hit_anchors(mutant)
        print('CUT54_CFG_SOURCE trees=4 positive=4 missing_duplicate_red=20 exact_cidr_anchors_unique=6')

    def test_condition_probe_both_main_boundaries(self):
        fixture_case=Cut54Generation()
        fixture_case.setUp()
        try:
            for label, source in [('old',fixture_case.old),('new',fixture_case.new)]:
                fixture_case.path.write_text(source)
                out=Path(fixture_case.tmp.name)/label
                with contextlib.redirect_stdout(io.StringIO()):
                    probe.generate(fixture_case.root,out)
                generated=(out/'condition.c').read_text()
                self.assertEqual(generated.count('int b1_condition_exact('),1)
                self.assertEqual(generated.count('int b1_condition_cidr('),1)
                self.assertTrue(generated.startswith(source))
                fixture_case.path.write_text(source.replace('int xdp_firewall_main(', 'int wrong_main('))
                with self.assertRaisesRegex(ValueError,'B1 main definition count'):
                    probe.generate(fixture_case.root,out/'red')
            print('CUT54_CONDITION_PROBE old=pass new=pass missing_main_red=2')
        finally:
            fixture_case.doCleanups()


if __name__=='__main__':unittest.main(verbosity=2)
