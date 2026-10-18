"""Retained historical checks independent of the retired Cut54 oracle."""
import json
import os
import re
import subprocess
import unittest
from unittest.mock import patch
from pathlib import Path
from compare import differences
from generate_p4_scenarios import build as historical
from generate_p5_scenarios import build
from reference_p4 import State


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


class ReferenceP5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.historical=historical()
        cls.root=Path(__file__).resolve().parents[2]

    def test_historical_protocols_unchanged(self):
        source=subprocess.run(['git','show','737ceec:node/agent/sync/cut5a_replay/reference_p4.py'],cwd=self.root,capture_output=True,text=True,check=True).stdout
        namespace={'__file__':str(Path(__file__).with_name('reference_p4.py')),'__name__':'frozen_p4'};exec(compile(source,'737ceec/reference_p4.py','exec'),namespace)
        count=0
        for scene in self.historical:
            for protocol in (3,4):
                # The oracle always offers both P3/P4; inputs for the p4/p5 cross
                # run are p4 on both. This equality checks semantics with the
                # exact same externally supplied winners on both models.
                a=namespace['State'](protocol).run(scene)[0];b=State(protocol).run(scene)[0]
                self.assertEqual(list(differences(a,b)),[],(scene['Name'],protocol));count+=1
        print('CUT55_HISTORICAL_MODEL protocols=2 scenes_per_protocol=%d equal_projections=%d'%(len(self.historical),count))


    def test_r1_retirement_waits_for_this_commit_receipt(self):
        from reference_p5 import State as P5State
        from reference_p4 import identity,LE32
        for fault in ('c-4',''):
            state=P5State(5)
            old=dict(id='old',logical_id=81,src_ip='192.0.2.81',protocol='tcp',action='drop')
            state.commit([dict(key=identity(old),rules=[old])])
            key=LE32(81)
            for name in ('id_counts','id_rl_states'):state.maps[name][key]='51'*16
            slot=state.config_slot
            state.remove('old',publish=False)  # Active delete succeeded; config copy did not flip.
            self.assertEqual(state.config_slot,slot);self.assertEqual(state.pending,{81})
            next_rule=dict(id='new',logical_id=82,src_ip='198.51.100.82',protocol='tcp',action='drop')
            status,body=state.commit([dict(key=identity(next_rule),rules=[next_rule])],fault)
            if fault:
                self.assertEqual(status,500);self.assertEqual(body['code'],'commit_failed')
                self.assertEqual(state.pending,{81});self.assertEqual(state.config_slot,slot)
                for name in ('id_counts','id_rl_states'):self.assertEqual(state.maps[name][key],'51'*16)
            else:
                self.assertEqual((status,body['receipt']),(200,'confirmed'));self.assertEqual(state.pending,set())
                for name in ('id_counts','id_rl_states'):self.assertNotIn(key,state.maps[name])
        print('CUT55_R1_MODEL_RECEIPT abort_retains=1 success_reclaims=1')


    def test_r1_deferred_prefix_recreated(self):
        from reference_p5 import State as P5State
        from reference_p4 import identity,LE32
        for side in ('src','dst'):
            state=P5State(5)
            old=dict(id='old',logical_id=71,protocol='tcp',action='drop',**{side+'_cidr':'192.0.2.0/24'})
            key=identity(old);state.commit([dict(key=key,rules=[old])])
            old_id=state.prefixes[side,'192.0.2.0/24']
            self.assertEqual(state.commit([dict(key=key,rules=[])],'Rc')[1]['receipt'],'deferred')
            new=dict(old,id='new',logical_id=72)
            status,body=state.commit([dict(key=key,rules=[new])])
            self.assertEqual((status,body['receipt']),(200,'confirmed'))
            new_id=state.prefixes[side,'192.0.2.0/24'];self.assertNotEqual(old_id,new_id)
            self.assertEqual(list(state.maps[side[0]+'v4_cidr_trie'].values()),[LE32(new_id)])
            self.assertIn(state.key(new),state.maps[state.name(new)])
        print('CUT55_R1_MODEL_PREFIX src=1 dst=1 republished=2')


    def test_generator_deterministic_and_additive(self):
        a=json.dumps(build(),indent=2)+'\n'
        self.assertEqual(a,Path(__file__).with_name('scenarios_commit_p5.json').read_text())
        self.assertTrue(all(s['Authority'].startswith('I15') for s in build()))
        for name in ('generate_scenarios.py','generate_p3_scenarios.py','generate_p4_scenarios.py','scenarios.json','scenarios_p3.json','scenarios_p4.json'):
            path=Path(__file__).with_name(name)
            if not path.exists():continue
            source=subprocess.run(['git','show','737ceec:node/agent/sync/cut5a_replay/'+name],cwd=self.root,capture_output=True,check=True).stdout
            self.assertEqual(path.read_bytes(),source,name)
        print('CUT55_GENERATOR additive=1 deterministic=1 historical_files_equal=1')


if __name__=='__main__':unittest.main()
