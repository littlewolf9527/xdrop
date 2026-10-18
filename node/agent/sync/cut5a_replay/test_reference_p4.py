"""Retained historical checks independent of the retired Cut54 oracle."""
import json
import os
import re
import subprocess
import unittest
from unittest.mock import patch
from pathlib import Path
from generate_p4_scenarios import build
from reference_p4 import State, LE32, LE64


def checked_go_test(name):
    """A successful process must prove that the selected test actually ran."""
    result = subprocess.run(
        ['go', 'test', './eval', '-run', '^'+name+'$', '-count=1', '-v'],
        cwd=Path(__file__).resolve().parents[2],
        env=dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local'),
        capture_output=True, text=True)
    output = result.stdout + result.stderr
    if result.returncode:
        raise AssertionError(output)
    if 'no tests to run' in output or not re.search(r'^=== RUN\s+'+re.escape(name)+r'$', output, re.M):
        raise AssertionError('selected Go test did not execute: '+name+'\n'+output)
    return result


class GoTestGuardTests(unittest.TestCase):
    def test_missing_go_test_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'selected Go test did not execute'):
            checked_go_test('TestTD117DeliberatelyMissingOracle')

    def test_verbose_identity_required(self):
        name = 'TestTD117GuardFixture'
        for output in ('ok example\n', 'testing: warning: no tests to run\n=== RUN   '+name+'\n'):
            with self.subTest(output=output):
                with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
                    with self.assertRaisesRegex(AssertionError, 'selected Go test did not execute'):
                        checked_go_test(name)
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '=== RUN   '+name+'\n--- PASS: '+name+' (0.00s)\n', '')):
            self.assertEqual(checked_go_test(name).returncode, 0)


class ReferenceP4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenes=build()

    def test_startup_whitelist_flip_precedes_rule_flip(self):
        cells=0
        for protocol in (3,4):
            for kind in ('exact','cidr'):
                scene=next(s for s in self.scenes if s['Name']=='I10_'+kind+'_startup')
                step=scene['Steps'][0]
                startup=State(protocol);startup.request(step)
                direct=State(protocol);direct.full(step['Body']['rules'])
                self.assertEqual((startup.config_slot,startup.slot),(0,1))
                self.assertEqual((direct.config_slot,direct.slot),(1,1))
                for state,active in ((startup,'config_a'),(direct,'config_b')):
                    self.assertEqual(state.maps[active][LE32(9)],LE64(1))
                for name in ('config_a','config_b'):
                    self.assertEqual(startup.maps[name][LE32(8)],LE64(1))
                count=6 if kind=='cidr' else 0
                self.assertEqual(startup.maps['config_a'][LE32(count)],LE64(int(protocol==3)))
                self.assertEqual(startup.maps['config_b'][LE32(count)],LE64(0))
                cells+=1
        print('CUT54_STARTUP_MODEL cells=%d config_flips=2 active_config=A rule_side=B observations=0'%cells)


if __name__=='__main__':unittest.main()
