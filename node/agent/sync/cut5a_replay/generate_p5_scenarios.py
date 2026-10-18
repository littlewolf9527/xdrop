#!/usr/bin/env python3
"""Protocol 5 additions; never writes any historical scenario or allow file."""
import copy
import json
from pathlib import Path
from generate_p4_scenarios import rule, step, request
from reference_p4 import identity
HERE=Path(__file__).parent

def group(probe,*rules):return dict(key=identity(probe),rules=list(rules))
def commit(name,groups,expect='committed',fault='',packets=('syn',)):
    return dict(Name=name,Method='POST',Path='/api/v1/rules/commit',Body=dict(groups=groups),Expect=expect,Fault=fault,Packets=list(packets))
def build():
    scenes=[]
    for iscidr in (False,True):
        kind='cidr' if iscidr else 'exact'
        a=rule('a',17,iscidr,dst_port=80);b=dict(a,tcp_flags='SYN');moved=dict(b,dst_port=0)
        # Empty request, create/replay/replace, cross-group move, condition -> pure,
        # identity-only replacement (same logical ID), delete, absent replay.
        renamed=dict(moved,id='renamed');renamed.pop('tcp_flags')
        scenes.append(dict(Name='I15_contract_'+kind,Authority='I15 H1-H6',Steps=[
            commit('empty',[],expect='unchanged'),commit('create',[group(a,a)]),
            commit('replay',[group(a,a)],expect='unchanged'),commit('condition',[group(a,b)]),
            commit('move',[group(a),group(moved,moved)]),commit('identity_pure',[group(moved,renamed)]),
            commit('delete',[group(moved)]),commit('absent',[group(moved)],expect='unchanged')]))
        for fault in ('c-2','R0','c-3','c-4','c-5','c-6','c-7','Rc','c-9'):
            if fault=='c-2' and not iscidr:continue
            expect='deferred' if fault=='Rc' else 'committed' if fault=='c-9' else 'withdrawal_pending' if fault=='c-2' else 'quiescence_failed' if fault=='R0' else 'commit_failed'
            u=rule('u',99,False,src_ip='203.0.113.99')
            scenes.append(dict(Name='I15_failure_'+kind+'_'+fault,Authority='I15 failure table',Steps=[
                commit('seed',[group(a,a)]),commit('fault',[group(a,b)],expect=expect,fault=fault),
                commit('recover',[group(u,u)])]))
    a=rule('a',17);other=dict(a,src_ip='203.0.113.1');u=rule('u',18,src_ip='203.0.113.18')
    reject_cases=[('empty_id',[group(a,dict(a,id=''))],'invalid'),('zero_id',[group(a,dict(a,logical_id=0))],'invalid'),
        ('key_mismatch',[group(a,other)],'invalid'),('duplicate_key',[group(a,a),group(a,a)],'invalid'),
        ('duplicate_id',[group(a,a,a)],'duplicate_id'),('duplicate_logical_id',[group(other,dict(other,id='b'))],'duplicate_logical_id'),
        ('group_undeclared',[group(other,other)],'group_undeclared'),('content_different',[group(a,dict(a,logical_id=18))],'content_different'),
        ('condition_capacity',[group(a,*[dict(a,id='r'+str(i),logical_id=20+i,ttl=str(60+i)) for i in range(5)])],'condition_capacity')]
    for name,groups,expect in reject_cases:
        scenes.append(dict(Name='I15_reject_'+name,Authority='I15 P1-P5',Steps=[commit('seed',[group(a,a)]),commit('reject',groups,expect=expect)]))
    bad=group(a,a);bad['key']['src_port']=None
    scenes.append(dict(Name='I15_reject_key',Authority='I15 P1 canonical key before member key',Steps=[
        commit('seed',[group(a,a)]),
        commit('reject_noncanonical_key',[bad],expect='invalid'),
        commit('reject_member_key_mismatch',[group(a,other)],expect='invalid')]))
    scenes.append(dict(Name='I15_table_full',Authority='I15 P7 M5b',Steps=[commit('seed',[group(a,a)]),commit('reject',[group(u,u)],expect='table_full',fault='capacity_one')]))
    c=rule('c',21,True);nested=dict(c,id='n',logical_id=22,src_cidr='192.0.2.0/25')
    scenes.append(dict(Name='I15_prefix_overlap',Authority='I15 P6',Steps=[commit('seed',[group(c,c)]),commit('reject',[group(c),group(nested,nested)],expect='cidr_overlap')]))
    # H3: changing one group preserves a second group's exact bytes and identity.
    scenes.append(dict(Name='I15_undeclared_preserved',Authority='I15 H3',Steps=[commit('seed',[group(a,a),group(u,u)]),commit('change',[group(a,dict(a,ttl='64'))])]))
    scenes.append(dict(Name='I15_failure_9b',Authority='I15 failure row 9b regression',Steps=[
        step('seed',[a]),request('copy_failure',dict(a,rate_limit=7),method='PUT',path='/api/v1/rules/a',p3='publish_failure',p4='publish_failure',fault='active_config_lookup')]))
    scenes.append(dict(Name='I15_failure_9c',Authority='I15 failure row 9c regression',Steps=[
        dict(Name='startup_refused',Method='STARTUP_CLEAR_FAILURE',Packets=[])]))
    scenes.append(dict(Name='I15_failure_10',Authority='I15 failure row 10 strict Step 1',Steps=[
        step('seed',[a]),step('strict_failure',[a],ExpectP3='publish_failure',ExpectP4='publish_failure',Fault='full_step1_delete'),commit('recover',[group(u,u)])]))
    scenes.append(dict(Name='I15_failure_9a',Authority='I15 failure row 9a payment receipt',Steps=[
        commit('seed',[group(a,a)]),request('retire',None,method='DELETE',path='/api/v1/rules/a'),
        commit('payment_failure',[group(u,u)],expect='table_full',fault='capacity_one_payment_failure')]))
    return scenes
if __name__=='__main__':
    scenes=build();(HERE/'scenarios_commit_p5.json').write_text(json.dumps(scenes,indent=2)+'\n')
    print('CUT55_SCENARIOS scenes=%d steps=%d packets=%d'%(len(scenes),sum(len(s['Steps']) for s in scenes),sum(len(v['Packets']) for s in scenes for v in s['Steps'])))
