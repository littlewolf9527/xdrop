import copy
import json
import unittest
from pathlib import Path
from compare import ABSENT, compare, differences
from generate_p6_scenarios import build
from reference_p5 import State as FrozenP5
from reference_p6 import State, DROP_ONLY, BOUNDED, IPV6, inputs

HERE=Path(__file__).parent

class Protocol6Tests(unittest.TestCase):
    def test_historical_model_has_no_semantic_forks(self):
        cases=0
        for name in ('scenarios_p4.json','scenarios_commit_p5.json'):
            for scene in json.loads((HERE/name).read_text()):
                frozen=FrozenP5(5).run(scene)
                old=State(5).run(scene);new=State(6).run(scene)
                self.assertEqual(old,frozen)
                self.assertEqual(old[1],new[1])
                ds=list(differences(old[0],new[0]))
                for path,a,b in ds:
                    self.assertEqual(path,('I9_protocol/welcome','body','sync_protocol'))
                    self.assertEqual((a,b),(5,6))
                cases+=len(scene['Steps'])
        print('CUT56_MODEL_HISTORY records=%d frozen_p5_unchanged=1 semantic_forks=0 protocol_only=1'%cases)

    def test_j8_accept_and_reject_domain(self):
        scenes=build();data=inputs(scenes)
        self.assertEqual(len(scenes),16)
        rate=both=rejected=0
        for scene in scenes:
            case=scene['Name']+'/install'
            old=State(5).run(scene)[0][case];new=State(6).run(scene)[0][case]
            commit=scene['Name'].endswith('_commit')
            if scene['Name'].startswith('J8_accept_rate_'):
                rate+=1;self.assertEqual(old['status'],400 if commit else 409);self.assertEqual(new['status'],200)
                self.assertEqual(data[case]['RulesP5'],[]);self.assertEqual(len(data[case]['RulesP6']),1)
            elif scene['Name'].startswith('J8_and_'):
                both+=1;self.assertEqual(old,new);self.assertEqual(new['status'],200)
            else:
                rejected+=1;self.assertEqual(old['status'],new['status']);self.assertEqual(old['installed'],new['installed'])
                want=IPV6 if '_ipv6_' in case else BOUNDED
                if commit:self.assertEqual(old['body']['error'],DROP_ONLY);self.assertEqual(new['body']['error'],want)
                else:self.assertEqual(old['body']['conflicts'][0]['reason'],DROP_ONLY);self.assertEqual(new['body']['conflicts'][0]['reason'],want)
        self.assertEqual((rate,both,rejected),(4,4,8))
        print('CUT56_MODEL_J8 accepted=4 and_regression=4 rejected=8')

    def test_cold_anomaly_bucket_uses_logical_id_and_divisor(self):
        scene=next(s for s in build() if s['Name']=='J8_accept_rate_exact_full')
        s=State(6,2,1);s.run(scene)
        r=s.installed[0];winner=dict(RuleID=r['id'])
        a=s.packet('length_mismatch',winner);b=s.packet('length_mismatch',winner)
        self.assertEqual((a['verdict'],b['verdict']),(2,1))
        self.assertEqual(s.maps['id_rl_states']['f1150000']['tokens'],[0,0])
        self.assertEqual(s.maps['id_rl_states']['f1150000']['last_update_present'],[False,True])
        self.assertEqual(s.maps['id_counts']['f1150000'],[2,1])
        print('CUT56_MODEL_RATE cold_pass=1 exhausted_drop=1 logical_id=5617 divisor=256')

    def test_j8_allowance_cannot_escape_scenario(self):
        old={'ordinary/install':{'status':400}};new={'ordinary/install':{'status':200}}
        row=dict(case='ordinary/install',field=['status'],old=400,new=200,authority='J8 forged outside scenario')
        self.assertEqual(len(compare(old,new,[])[1]),1)
        with self.assertRaisesRegex(ValueError,'J8 allowance must belong'):
            compare(old,new,[row])
        print('CUT56_J8_BOUNDARY scenario_escape_red=1')

    def test_j8_rejected_only_allows_error_text(self):
        case='J8_rejected_unbounded_exact_full/install'
        old={case:{'body':{'error':'old','conflicts':[{'reason':'old'}]},'status':409,'installed':{},'maps_before_packets':{},'packets':[{'verdict':2}]}}
        for path in (['status'],['installed','count'],['maps_before_packets','row'],['packets',0,'verdict'],['body','code'],['body','error','extra']):
            row=dict(case=case,field=path,old='old',new='new',authority='J8 forged rejected state')
            with self.assertRaisesRegex(ValueError,'J8 still-rejected allowance must be a body error-text field'):
                compare(old,old,[row])
        new=copy.deepcopy(old);new[case]['status']=200
        self.assertEqual(len(compare(old,new,[])[1]),1)
        row=dict(case=case,field=['status'],old=409,new=200,authority='J8 forged rejected status')
        with self.assertRaises(ValueError):compare(old,new,[row])
        new=copy.deepcopy(old);new[case]['body']['conflicts'][0]['reason']='new'
        row=dict(case=case,field=['body','conflicts',0,'reason'],old='old',new='new',authority='J8 legitimate error text')
        self.assertEqual(tuple(map(len,compare(old,new,[row]))),(1,0))
        print('CUT56_J8_BOUNDARY rejected_state_red=1 exact_message_positive=1')

if __name__=='__main__':unittest.main()
