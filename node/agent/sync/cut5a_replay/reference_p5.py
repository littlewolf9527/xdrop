#!/usr/bin/env python3
"""Protocol 4/5 projections and p5-only commit records, no observed input."""
import argparse
import json
from pathlib import Path
from compare import differences,validate_cut55_authority
from reference_p3 import canonical
from reference_p4 import State as HistoricalState, groupkey, identity

class State(HistoricalState):
    def commit(self,groups,fault=''):
        if self.protocol<5:return super().commit(groups,fault)
        # Ordered request-local preflight: raw JSON null ports are not canonical
        # typed zero ports. Keep earlier groups' member/capacity guards ahead of
        # later keys, without modifying the historical model's implementation.
        def reject(i,code,error,status=409,**extra):
            return status,dict(code=code,error=error,groups=[dict(index=i,code=code,error=error,**extra)],withdrawal_pending=False)
        declared=set();ids={};logical={}
        for i,g in enumerate(groups):
            key=g['key'];probe={k:v for k,v in key.items() if k!='kind'}
            for port in ('src_port','dst_port'):
                if probe.get(port) is None:probe[port]=0
            if key!=identity(probe):return reject(i,'validation_rejected','key must use its canonical form',400)
            k=groupkey(probe)
            if k in declared:return reject(i,'validation_rejected','key occurs in more than one group',400)
            declared.add(k);rules=[]
            for incoming in g['rules']:
                if not incoming.get('id'):return reject(i,'validation_rejected','rule id must be nonempty',400)
                r=canonical(incoming)
                if not r.get('logical_id'):return reject(i,'validation_rejected','logical_id must be nonzero',400)
                if groupkey(r)!=k:return reject(i,'validation_rejected','rule key differs from declared group key',400)
                if r['id'] in ids:
                    first=ids[r['id']];status,body=reject(first,'duplicate_id','rule ID occurs more than once in request',rule_id=r['id'])
                    if first!=i:body['groups'].append(dict(body['groups'][0],index=i))
                    return status,body
                ids[r['id']]=i
                if r['logical_id'] in logical:return reject(i,'duplicate_logical_id','logical ID is held by rule '+json.dumps(logical[r['logical_id']]))
                logical[r['logical_id']]=r['id'];rules.append(r)
            if len(rules)>4:
                occupied=sorted(r['id'] for r in rules)
                return reject(i,'condition_capacity','physical candidates %d exceed 4; occupying rule IDs: %s'%(len(rules),','.join(occupied)),rule_ids=occupied)
        self._commit_entry_slot=self.config_slot
        try:
            return super().commit(groups,fault)
        finally:
            self._commit_entry_slot=None

    def reclaim_commit(self):
        # The shared historical helper calls this at both step 3 and step 9.
        # P5 R1 defers logical retirement until the latter, after the flip and
        # successful Rc; a pure-delete config failure can leave step 3 without
        # any receipt since retirement. Historical protocol behavior is intact.
        if self.protocol>=5 and getattr(self,'_commit_entry_slot',None)==self.config_slot:
            return
        return super().reclaim_commit()

    def request(self,step):
        status,body=super().request(step)
        if (self.protocol>=5 and step['Method']=='PUT' and step.get('Fault')=='active_config_lookup'
                and status==500 and body.get('code')=='internal_error'):
            # POST's literal error is already its full response; PUT wraps the
            # closed-config Lookup error. Both suites compare the complete text.
            body['error']='config publish failed: failed to read active config index 0: lookup: bad file descriptor'
        return status,body

def inputs(scenes,commit=False):
    out={}
    for scene in scenes:
        a=State(5 if commit else 4).run(scene)[1];b=State(5).run(scene)[1]
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name']
            out[case]=dict(RulesP3=a[case],RulesP4=b[case],Packets=step['Packets'])
    return out

def records_and_table(scenes,oracle,cpus=1,cpu=0,commit=False):
    old,new,table={},{},[]
    for scene in scenes:
        a=State(5 if commit else 4,cpus,cpu).run(scene,oracle)[0]
        b=State(5,cpus,cpu).run(scene,oracle)[0]
        old.update(a);new.update(b)
        for path,x,y in differences(a,b):
            token='I15' if path[1:]==('body','sync_protocol') else 'I16'
            row=dict(case=path[0],field=list(path[1:]),old=x,new=y,authority=token+' PLAN ④-1 / authorization 3')
            validate_cut55_authority(row,a,b);table.append(row)
    return old,new,table

def main():
    p=argparse.ArgumentParser();p.add_argument('--scenarios',type=Path,required=True);p.add_argument('--commit',action='store_true')
    p.add_argument('--oracle-input',type=Path);p.add_argument('--oracle',type=Path);p.add_argument('--possible-cpus',type=int,default=1);p.add_argument('--packet-cpu',type=int,default=0)
    p.add_argument('--output',type=Path);p.add_argument('--expected',type=Path);p.add_argument('--baseline-expected',type=Path);p.add_argument('--prepared-scenarios',type=Path)
    a=p.parse_args();scenes=json.loads(a.scenarios.read_text())
    if a.oracle_input:
        v=inputs(scenes,a.commit);a.oracle_input.write_text(json.dumps(v,indent=2)+'\n');print('CUT55_ORACLE_INPUT cases=%d observations=0'%len(v));return
    oracle=json.loads(a.oracle.read_text());old,new,table=records_and_table(scenes,oracle,a.possible_cpus,a.packet_cpu,a.commit)
    for scene in scenes:
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name'];step['HitsP4']=[bool(x['RuleID']) for x in oracle[case]['P4']]
    for path,value in ((a.output,table),(a.expected,new),(a.baseline_expected,old),(a.prepared_scenarios,scenes)):
        if path:path.write_text(json.dumps(value,indent=2)+'\n')
    print('CUT55_MODEL records=%d allowed=%d commit=%d observations=0'%(len(new),len(table),a.commit))
if __name__=='__main__':main()
