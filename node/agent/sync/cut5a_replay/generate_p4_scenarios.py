#!/usr/bin/env python3
"""Additive 5-4 scenarios. Historical p2/p3 scenario files are never rewritten."""
import copy
import json
from pathlib import Path
from generate_p3_scenarios import build as historical
HERE=Path(__file__).parent

def rule(id='r',logical=17,cidr=False,**kw):
    r=dict(id=id,logical_id=logical,protocol='tcp',action='drop')
    r['src_cidr' if cidr else 'src_ip']='192.0.2.0/24' if cidr else '192.0.2.1';r.update(kw);return r

def step(name,rules,packets=('syn',),**kw):
    out=dict(Name=name,Method='POST',Path='/api/v1/sync/atomic',Body=dict(rules=rules),ExpectP3='success',ExpectP4='success',Packets=list(packets),Fault='');out.update(kw);return out

def request(name,body,method='POST',path='/api/v1/rules',packets=('syn',),p3='success',p4='success',fault=''):
    return dict(Name=name,Method=method,Path=path,Body=body,ExpectP3=p3,ExpectP4=p4,Packets=list(packets),Fault=fault)

def build():
    out=copy.deepcopy(historical())
    for s in out:s['Authority']='I11b / I12b structural migration' if s['Authority']=='unchanged' else s['Authority']
    for iscidr in (False,True):
        kind='cidr' if iscidr else 'exact'
        a=rule(cidr=iscidr,dst_port=80);moved=rule(cidr=iscidr)
        out.append(dict(Name='I11b_'+kind+'_move',Authority='I11b',Steps=[step('seed',[a]),step('move',[moved]),step('same',[moved])]))
        b=rule('b',18,iscidr,dst_port=443)
        a2,b2=copy.deepcopy(a),copy.deepcopy(b);a2['dst_port'],b2['dst_port']=443,80
        out.append(dict(Name='I11b_'+kind+'_swap',Authority='I11b',Steps=[step('seed',[a,b]),step('swap',[a2,b2])]))
        cond=dict(a,tcp_flags='SYN')
        out.append(dict(Name='I11b_'+kind+'_pure_condition',Authority='I11b',Steps=[step('pure',[a]),step('condition',[cond]),step('pure_again',[a])]))
        ra=dict(a,action='rate_limit',rate_limit=1);rm=dict(moved,action='rate_limit',rate_limit=1);rc=dict(ra,tcp_flags='SYN')
        out.append(dict(Name='I12b_'+kind+'_move',Authority='I12b',Steps=[step('seed',[ra],['rate']),step('move',[rm]),step('same',[rm])]))
        rb=dict(b,action='rate_limit',rate_limit=1);ra2,rb2=dict(ra,dst_port=443),dict(rb,dst_port=80)
        out.append(dict(Name='I12b_'+kind+'_swap',Authority='I12b',Steps=[step('seed',[ra,rb],['rate']),step('swap',[ra2,rb2])]))
        out.append(dict(Name='I12b_'+kind+'_pure_condition',Authority='I12b',Steps=[step('pure',[ra],['rate']),step('condition',[rc]),step('pure_again',[ra])]))
        out.append(dict(Name='I12b_'+kind+'_rate_drop_rate',Authority='I12b',Steps=[step('seed',[ra],['rate']),request('drop',a,'PUT','/api/v1/rules/r'),request('rate_again',ra,'PUT','/api/v1/rules/r')]))
        z=rule(cidr=iscidr,logical=0)
        for entry in ('post','put_missing','batch','full','startup'):
            if entry=='post':steps=[request('zero',z,p4='invalid')]
            elif entry=='put_missing':steps=[request('zero',z,'PUT','/api/v1/rules/r',p3='missing',p4='invalid')]
            elif entry=='batch':steps=[request('zero',dict(rules=[z]),path='/api/v1/rules/batch',p4='partial_rejection')]
            elif entry=='full':steps=[step('zero',[z],ExpectP4='partial_rejection')]
            else:steps=[dict(Name='zero',Method='RESTART',Body=dict(rules=[z]),Packets=['syn'])]
            out.append(dict(Name='I10_'+kind+'_'+entry,Authority='I10',Steps=steps))
        out.append(dict(Name='I10_'+kind+'_replay_missing',Authority='I10',Steps=[step('seed',[a]),request('replay',dict(a,logical_id=0),p3='content_different',p4='invalid')]))
        old=rule(cidr=iscidr)
        incoming=rule('new',18,iscidr)
        incoming['src_cidr' if iscidr else 'src_ip']='198.51.100.0/24' if iscidr else '198.51.100.1'
        out.append(dict(Name='I17b_'+kind+'_single',Authority='I17b',Steps=[step('seed',[old],[]),request('full',incoming,p4='table_full',fault='capacity_one')]))
        out.append(dict(Name='I17b_'+kind+'_batch',Authority='I17b',Steps=[step('seed',[old],[]),request('partial',dict(rules=[old,incoming]),path='/api/v1/rules/batch',p4='partial_rejection',fault='capacity_one')]))
    for missing in ('source','destination'):
        a=dict(id='alias',logical_id=17,protocol='tcp',action='drop')
        b=dict(id='winner',logical_id=18,protocol='tcp',action='drop',dst_port=80)
        c=dict(id='enabler',logical_id=19,src_cidr='203.0.113.0/24',dst_cidr='198.51.100.0/24',protocol='tcp',action='drop',src_port=1234)
        if missing=='source':a.update(dst_cidr='198.51.100.0/24',src_port=1234);b.update(dst_cidr='198.51.100.0/24')
        else:
            a.update(src_cidr='192.0.2.0/24',src_port=1234);b.update(src_cidr='192.0.2.0/24');c.update(src_cidr='192.0.2.0/24',dst_cidr='203.0.113.0/24')
        x=rule('exact-miss',20,src_ip='203.0.113.1')
        out.append(dict(Name='J9_'+missing+'_enabler',Authority='J9',Steps=[step('before',[a,b,x]),step('enabled',[a,b,c,x]),step('withdraw',[a,b,x])]))
    return out
if __name__=='__main__':
    scenes=build();(HERE/'scenarios_p4.json').write_text(json.dumps(scenes,indent=2)+'\n')
    print('CUT54_REPLAY_SCENARIOS scenes=%d steps=%d packets=%d'%(len(scenes),sum(len(s['Steps']) for s in scenes),sum(len(v['Packets']) for s in scenes for v in s['Steps'])))
