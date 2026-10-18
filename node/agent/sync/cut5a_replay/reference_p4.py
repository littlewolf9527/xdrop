#!/usr/bin/env python3
"""Finite protocol 3/4 API and state specification. No observed replay input.

Winner selection is exclusively supplied by eval's independent old/new B1
entry points. Historical p3 helpers below supply wire encoding and JSON syntax,
never their decision or packet model. CPU topology remains an explicit input.
"""
import argparse
import copy
import ipaddress
import json
import struct
from pathlib import Path
from compare import differences
from reference_p3 import canonical, condition_wire, extended, strictness, response_projection

HERE=Path(__file__).parent
LE32=lambda n:struct.pack('<I',n).hex()
LE64=lambda n:struct.pack('<Q',n).hex()
RULE_MAPS=('blacklist','blacklist_b','cidr_blacklist','cidr_blist_b')
COND_MAPS=('cond_a','cond_b','cidr_cond_a','cidr_cond_b')
MASKS={0:31,1:30,2:26,3:18,4:2,5:16,6:4,7:8,8:1,9:17,10:3,11:9,12:10,13:19,14:25,15:20,16:24,17:5,18:21,21:11,22:27,23:13,24:29,25:6,26:22,27:12,28:28,29:7,30:23,31:14,33:15}
PROTO={'':0,'all':0,'tcp':6,'udp':17,'icmp':1,'icmpv6':58}
def cidr(r):return bool(r.get('src_cidr') or r.get('dst_cidr'))
def combo(r):
    m=int(bool(r.get('src_ip') or r.get('src_cidr')))|int(bool(r.get('dst_ip') or r.get('dst_cidr')))<<1|int(bool(r.get('src_port')))<<2|int(bool(r.get('dst_port')))<<3|int(bool(PROTO[r.get('protocol','')]))<<4
    return next(k for k,v in MASKS.items() if v==m)
def groupkey(r):return tuple(r.get(k,0 if k.endswith('port') else '') for k in ('src_ip','dst_ip','src_cidr','dst_cidr','src_port','dst_port','protocol'))
def identity(r):
    out={'kind':'cidr' if cidr(r) else 'exact'}
    for k in ('src_ip','dst_ip','src_cidr','dst_cidr'):
        if r.get(k):out[k]=r[k]
    out.update(src_port=r.get('src_port',0),dst_port=r.get('dst_port',0),protocol=r.get('protocol','all'))
    return out

def wire(r,flag,p4,counts=(0,0)):
    b=bytearray(32)
    b[0]=2 if r['action']=='rate_limit' else 1
    struct.pack_into('<I',b,4,r.get('rate_limit',0))
    if p4:struct.pack_into('<I',b,8,r.get('logical_id',0))
    else:struct.pack_into('<QQ',b,8,*counts)
    b[28]=int(flag)
    return b.hex()

class State:
    def __init__(self,protocol,cpus=1,packet_cpu=0):
        self.protocol,self.cpus,self.packet_cpu=protocol,cpus,packet_cpu
        self.slot=self.config_slot=0
        self.installed=[];self.groups=[];self.prefixes={};self.next_prefix=1;self.pending=set()
        names=RULE_MAPS+COND_MAPS+('sv4_cidr_trie','dv4_cidr_trie','sv6_cidr_trie','dv6_cidr_trie','id_counts','id_rl_states')
        if protocol==3:names+=('rl_states','cidr_rl_states')
        self.maps={n:{} for n in names}
        for n in ('config_a','config_b'):self.maps[n]={LE32(i):LE64(0) for i in range(12)}
        self.maps['active_config']={LE32(0):LE64(0)}
        self.maps['stats']={LE32(i):[0] for i in range(5)}
        self.times={};self.now=10_000_000_000
    def name(self,r,condition=False,slot=None):return (COND_MAPS if condition else RULE_MAPS)[2*int(cidr(r))+(self.slot if slot is None else slot)]
    def key(self,r):
        if cidr(r):
            ids=[self.prefixes[(side,r[side+'_cidr'])] if r.get(side+'_cidr') else 0 for side in ('src','dst')]
            return (struct.pack('<II',*ids)+struct.pack('>HH',r.get('src_port',0),r.get('dst_port',0))+bytes([PROTO[r.get('protocol','')],0,0,0])).hex()
        def ip(k):
            if not r.get(k):return bytes(16)
            x=ipaddress.ip_address(r[k]);return bytes(10)+b'\xff\xff'+x.packed if x.version==4 else x.packed
        return (ip('src_ip')+ip('dst_ip')+struct.pack('>HH',r.get('src_port',0),r.get('dst_port',0))+bytes([PROTO[r.get('protocol','')],0,0,0])).hex()
    def grouped(self,rules):
        groups={}
        for r in rules:groups.setdefault(groupkey(r),[]).append(r)
        return list(groups.values())
    def condition(self,r):return next(len(g)>1 or extended(g[0]) for g in self.groups if r in g)
    def reserve(self,r):
        for side in ('src','dst'):
            prefix=r.get(side+'_cidr')
            if prefix and (side,prefix) not in self.prefixes:
                self.prefixes[side,prefix]=self.next_prefix;self.next_prefix+=1
    def tries(self):
        valid={(side,r[side+'_cidr']) for r in self.installed for side in ('src','dst') if r.get(side+'_cidr')}
        self.prefixes={k:v for k,v in self.prefixes.items() if k in valid}
        for n in ('sv4_cidr_trie','dv4_cidr_trie','sv6_cidr_trie','dv6_cidr_trie'):self.maps[n]={}
        for (side,prefix),value in self.prefixes.items():
            net=ipaddress.ip_network(prefix)
            k=(struct.pack('<I',net.prefixlen)+net.network_address.packed).hex()
            self.maps[('s' if side=='src' else 'd')+f'v{net.version}_cidr_trie'][k]=LE32(value)
    def publish(self):
        config=copy.deepcopy(self.maps[('config_a','config_b')[self.config_slot]])
        for iscidr,count,bitmap in ((False,0,2),(True,6,7)):
            groups=[g for g in self.groups if cidr(g[0])==iscidr]
            config[LE32(count)]=LE64(len(groups))
            bits=0
            for g in groups:bits|=1<<combo(g[0])
            config[LE32(bitmap)]=LE64(bits)
        config[LE32(9)]=LE64(self.slot)
        if self.protocol==3:config[LE32(10)]=LE64(0)
        self.config_slot=1-self.config_slot
        self.maps[('config_a','config_b')[self.config_slot]]=config
        self.maps['active_config'][LE32(0)]=LE64(self.config_slot)
    def reject(self,code,error,status=409,**extra):return status,dict(code=code,error=error,withdrawal_pending=False,**extra)
    def table_full(self,used,cap):return self.reject('table_full',f'logical state capacity {used} exceeds {cap}; batch not published')
    def full(self,rules,fault=''):
        rules=copy.deepcopy(rules)
        if fault=='zero_logical_id':rules[0]['logical_id']=0
        for g in self.grouped(rules):
            if not (len(g)>1 or extended(g[0])):continue
            reason=None
            if any(not r.get('logical_id') for r in g):reason='missing/duplicate logical_id 0'
            if len(g)>4:reason='physical candidates %d exceed 4; occupying rule IDs: %s'%(len(g),','.join(sorted(r['id'] for r in g)))
            if reason:return self.reject('condition_group_invalid','condition group invalid; batch not published',key=identity(g[0]),conflicts=[dict(id=r['id'],reason=reason) for r in g],added=0,failed=1)
        valid=[r for r in rules if self.protocol==3 or r.get('logical_id')]
        union={r['logical_id'] for r in self.installed+valid if r.get('logical_id')}|self.pending
        if fault=='capacity_one' and len(union)>1:
            _,body=self.table_full(len(union),1);body.update(added=0,failed=1);return 409,body
        rejected=[dict(id=r['id'],reason='logical_id must be nonzero') for r in rules if self.protocol>=4 and not r.get('logical_id')]
        if self.protocol>=5 and fault=='full_step1_delete':return 500,dict(error='clear shadow blacklist: delete: injected full_step1_delete',added=0,failed=1,withdrawal_pending=False)
        accepted=[canonical(r) for r in valid]
        shadow=1-self.slot
        for n in (RULE_MAPS[shadow],RULE_MAPS[2+shadow],COND_MAPS[shadow],COND_MAPS[2+shadow]):self.maps[n]={}
        groups=self.grouped(accepted)
        for r in accepted:self.reserve(r)
        for g in groups:
            cond=len(g)>1 or extended(g[0]);r=sorted(g,key=lambda x:(-strictness(x),x.get('logical_id',0)))[0] if cond else g[0]
            self.maps[self.name(r,slot=shadow)][self.key(r)]=wire(r,cond,self.protocol>=4)
            if cond:self.maps[self.name(r,True,shadow)][self.key(r)]=condition_wire(g)
        self.installed,self.groups,self.slot=accepted,groups,shadow
        self.publish()
        for names in (RULE_MAPS[:2],RULE_MAPS[2:],COND_MAPS[:2],COND_MAPS[2:]):
            self.maps[names[1-shadow]]=copy.deepcopy(self.maps[names[shadow]]) if self.protocol>=5 else {}
        self.tries()
        ids={LE32(r['logical_id']) for r in accepted if r.get('logical_id')}
        for n in ('id_counts','id_rl_states'):self.maps[n]={k:v for k,v in self.maps[n].items() if k in ids}
        self.times={k:v for k,v in self.times.items() if k[0]!='id_rl_states' or k[1] in ids};self.pending=set()
        return 200,dict(success=True,added=len(accepted),failed=len(rejected),rules=sum(not cidr(r) for r in accepted),cidr_rules=sum(cidr(r) for r in accepted),rejected=rejected,withdrawal_pending=False)
    def mirror(self):
        for names in (RULE_MAPS[:2],RULE_MAPS[2:],COND_MAPS[:2],COND_MAPS[2:]):
            self.maps[names[1-self.slot]]=copy.deepcopy(self.maps[names[self.slot]])
    def commit(self,groups,fault=''):
        if self.protocol<5:raise ValueError('commit is unavailable before protocol 5')
        def reject(i,code,error,status=409,**extra):
            entry=dict(index=i,code=code,error=error,**extra)
            return status,dict(code=code,error=error,groups=[entry],withdrawal_pending=False)
        def failed(code,error):return 500,dict(code=code,error=error,groups=[],withdrawal_pending=False)
        declared={};ids={};logical={};prepared=[]
        for i,g in enumerate(groups):
            key=g['key'];probe={k:v for k,v in key.items() if k!='kind'}
            if key!=identity(probe):return reject(i,'validation_rejected','key must use its canonical form',400)
            k=groupkey(probe)
            if k in declared:return reject(i,'validation_rejected','key occurs in more than one group',400)
            declared[k]=i;rules=[]
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
            prepared.append((i,probe,rules))
        for i,probe,rules in prepared:
            for r in rules:
                old=next((x for x in self.installed if x['id']==r['id']),None)
                if old:
                    if groupkey(old) not in declared:return reject(i,'group_undeclared','rule ID belongs to an undeclared group',undeclared_key=identity(old),rule_id=r['id'])
                    if old['logical_id']!=r['logical_id']:return reject(i,'content_different','logical identity can only change through full sync')
                owner=next((x for x in self.installed if x['logical_id']==r['logical_id'] and x['id']!=r['id']),None)
                if owner and groupkey(owner) not in declared:return reject(i,'duplicate_logical_id','logical ID is held by rule '+json.dumps(owner['id']))
        union=set(self.prefixes)
        for i,probe,rules in prepared:
            if not rules:continue
            for side in ('src','dst'):
                prefix=probe.get(side+'_cidr')
                if not prefix:continue
                network=ipaddress.ip_network(prefix)
                for direction,other in sorted(union):
                    net=ipaddress.ip_network(other)
                    if side==direction and network.version==net.version and network!=net and network.overlaps(net):
                        return reject(i,'cidr_overlap','prefix %s overlaps %s'%(prefix,other))
                union.add((side,prefix))
        results=[];changed=[]
        for i,probe,rules in prepared:
            old=[r for r in self.installed if groupkey(r)==groupkey(probe)]
            different=sorted(old,key=lambda r:r['id'])!=sorted(rules,key=lambda r:r['id'])
            outcome='unchanged' if not different else 'deleted' if not rules else 'created' if not old else 'replaced'
            results.append(dict(index=i,result=outcome))
            if different:changed.append((i,probe,rules))
        if not changed:return 200,dict(code='unchanged',groups=results,withdrawal_pending=False)
        if fault in ('capacity_one','capacity_one_payment_failure'):
            used=len({r['logical_id'] for r in self.installed}|set(logical)|self.pending)
            if used>1:return reject(0,'table_full','logical_state capacity exceeded by %d rows'%(used-1),table='logical_state',excess=used-1)
        if fault=='c-2':return failed('withdrawal_pending','injected c-2')
        if fault=='R0':return failed('quiescence_failed','quiescence failed after 3 attempts: injected R0')
        if fault=='c-3':return failed('commit_failed','injected c-3')
        self.mirror();self.tries();self.reclaim_commit()
        old_prefixes=copy.deepcopy(self.prefixes)
        target=[r for r in self.installed if groupkey(r) not in declared]+[r for _,_,rules in prepared for r in rules]
        for _,_,rules in changed:
            for r in rules:self.reserve(r)
        shadow=1-self.slot
        if fault!='c-4':
            for _,probe,rules in changed:
                try:k=self.key(probe)
                except KeyError:continue # deleting an absent CIDR group
                rule_name,cond_name=self.name(probe,slot=shadow),self.name(probe,True,shadow)
                self.maps[rule_name].pop(k,None);self.maps[cond_name].pop(k,None)
                if rules:
                    conditional=len(rules)>1 or extended(rules[0])
                    representative=sorted(rules,key=lambda r:(-strictness(r),r['logical_id']))[0] if conditional else rules[0]
                    self.maps[rule_name][k]=wire(representative,conditional,True)
                    if conditional:self.maps[cond_name][k]=condition_wire(rules)
        if fault in ('c-4','c-5'):
            self.prefixes=old_prefixes
            return failed('commit_failed','injected '+fault)
        # Build the shadow config without changing the active selector.
        old_installed,old_groups=self.installed,self.groups
        self.installed,self.groups=target,self.grouped(target)
        prior_slot,prior_config=self.slot,self.config_slot
        self.slot=shadow;self.publish()
        self.config_slot=prior_config;self.slot=prior_slot
        self.maps['active_config'][LE32(0)]=LE64(prior_config)
        self.installed,self.groups=old_installed,old_groups
        if fault in ('c-6','c-7'):
            self.prefixes=old_prefixes
            return failed('commit_failed','injected '+fault)
        old_ids={r['logical_id'] for r in self.installed};new_ids={r['logical_id'] for r in target}
        self.pending|=old_ids-new_ids
        self.installed,self.groups,self.slot=target,self.grouped(target),shadow
        self.config_slot=1-prior_config;self.maps['active_config'][LE32(0)]=LE64(self.config_slot)
        # Publication retains exiting prefixes through Rc.
        keep=self.installed;self.installed=old_installed+target;self.tries();self.installed=keep
        receipt='deferred' if fault=='Rc' else 'confirmed'
        if receipt=='confirmed':
            if fault!='c-9':self.mirror()
            self.tries();self.reclaim_commit()
        return 200,dict(code='committed',groups=results,receipt=receipt,withdrawal_pending=False)
    def reclaim_commit(self):
        valid={r['logical_id'] for r in self.installed}
        for logical in self.pending-valid:
            for name in ('id_counts','id_rl_states'):
                self.maps[name].pop(LE32(logical),None);self.times.pop((name,LE32(logical)),None)
        self.pending=set()
    def preflight(self,rules):
        combined={r['id']:r for r in self.installed}
        touched={groupkey(r) for r in rules}
        for r in rules:
            if r['id'] in combined and extended(combined[r['id']]):return combined[r['id']]
            combined[r['id']]=r
        for g in self.grouped(list(combined.values())):
            if groupkey(g[0]) in touched and (len(g)>1 or extended(g[0])):return g[0]
        return None
    def add(self,r,capacity=None,publish=True):
        r=canonical(r)
        if self.protocol>=4 and not r.get('logical_id'):return 'validation_rejected','logical_id must be nonzero'
        old=next((x for x in self.installed if x['id']==r['id']),None)
        if old:return ('already_exists','') if old==r else ('content_different','')
        if capacity and self.protocol>=4:
            u=len({x.get('logical_id',0) for x in self.installed+[r]}|self.pending)
            if u>capacity:return 'table_full',f'logical state capacity {u} exceeds {capacity}; batch not published'
        self.reserve(r);self.maps[self.name(r)][self.key(r)]=wire(r,False,self.protocol>=4)
        self.installed.append(r);self.groups=self.grouped(self.installed);self.tries()
        if publish:self.publish()
        return 'success',''
    def remove(self,id,publish=True):
        r=next(x for x in self.installed if x['id']==id);k=self.key(r)
        del self.maps[self.name(r)][k]
        if self.protocol==3:
            n='cidr_rl_states' if cidr(r) else 'rl_states';self.maps[n].pop(k,None);self.times.pop((n,k),None)
        if r.get('logical_id'):self.pending.add(r['logical_id'])
        self.installed.remove(r);self.groups=self.grouped(self.installed);self.tries()
        if publish:self.publish()
    def request(self,step):
        method,path=step['Method'],step.get('Path','');body=step.get('Body');fault=step.get('Fault','')
        if method=='GET':return 200,dict(sync_protocol=self.protocol,name='XDrop Agent',version='2.6.1',status='running',features=['ipv4','ipv6','rate_limit','decoder_sugar','anomaly_match'])
        if method=='RESTART':
            self.__init__(self.protocol,self.cpus,self.packet_cpu)
            # NewHandlers starts config/rule/WL selectors at A. SyncOnStartup
            # publishes even the empty whitelist BEFORE DoAtomicSync. That
            # copies A -> B, changes only WL slots (1/3/8), then flips config.
            # The blacklist sync consequently writes config A and rule side B.
            config=copy.deepcopy(self.maps['config_a'])
            config[LE32(1)]=LE64(0);config[LE32(3)]=LE64(0);config[LE32(8)]=LE64(1)
            self.maps['config_b']=config;self.config_slot=1
            self.maps['active_config'][LE32(0)]=LE64(1)
            self.full(body['rules']);return None,None
        if path=='/api/v1/rules/commit':return self.commit(body['groups'],fault)
        if path=='/api/v1/sync/atomic':return self.full(body['rules'],fault)
        if method=='DELETE':
            ids=body['ids'] if path.endswith('/batch') else [path.rsplit('/',1)[1]]
            for id in ids:self.remove(id,False)
            self.publish()
            if path.endswith('/batch'):return 200,dict(success=True,deleted=len(ids),failed=0,results=[dict(id=id,code='success') for id in ids],withdrawal_pending=False)
            return 200,dict(success=True,message='Rule deleted',code='success',withdrawal_pending=False)
        rules=body['rules'] if path.endswith('/batch') else [body]
        group=self.preflight(rules)
        if group:return self.reject('condition_group_required','condition five-tuple requires a whole-group write',key=identity(group))
        if fault=='active_config_lookup':return self.reject('internal_error','config publish failed',500)
        if method=='PUT':
            r=canonical(body)
            if self.protocol>=4 and not r.get('logical_id'):return self.reject('validation_rejected','logical_id must be nonzero',400)
            old=next((x for x in self.installed if x['id']==r['id']),None)
            if old is None:return self.reject('rule_not_found','Rule not found',404)
            if old.get('logical_id',0)!=r.get('logical_id',0):return self.reject('content_different','rule content differs')
            k=self.key(old);n=self.name(old);counts=(0,0)
            if self.protocol==3:
                counts=struct.unpack_from('<QQ',bytes.fromhex(self.maps[n][k]),8)
                if old['action']=='rate_limit' and r['action']!='rate_limit':
                    bucket='cidr_rl_states' if cidr(r) else 'rl_states';self.maps[bucket].pop(k,None);self.times.pop((bucket,k),None)
            self.maps[n][k]=wire(r,False,self.protocol>=4,counts)
            self.installed[self.installed.index(old)]=r;self.groups=self.grouped(self.installed);self.publish()
            return 200,dict(success=True,rule_id=r['id'],code='updated',withdrawal_pending=False)
        capacity=1 if fault=='capacity_one' else None
        if path.endswith('/batch'):
            results=[];added=failed=0;exact_written=False
            for r in sorted(rules,key=lambda r:not cidr(r)):
                code,error=self.add(r,capacity,publish=cidr(r));entry=dict(id=r['id'],code=code)
                if error:entry['error']=error
                results.append(entry)
                if code in ('success','already_exists'):added+=1
                else:failed+=1
                if code=='success' and not cidr(r):exact_written=True
            if exact_written:self.publish()
            return 200,dict(success=True,added=added,failed=failed,results=results,withdrawal_pending=False)
        code,error=self.add(body,capacity)
        if code=='validation_rejected':return self.reject(code,error,400)
        if code=='table_full':return self.reject(code,error)
        if code=='content_different':return self.reject(code,'rule content differs')
        out=dict(success=True,rule_id=body['id'],code=code,withdrawal_pending=False)
        if code=='success':out['message']='CIDR rule added' if cidr(body) else 'Rule added'
        return 200,out
    def counters(self):
        out={}
        if self.protocol==3:
            for n in RULE_MAPS:
                for k,v in self.maps[n].items():
                    a,b=struct.unpack_from('<QQ',bytes.fromhex(v),8);out[n+'/'+k+'/match']=a;out[n+'/'+k+'/drop']=b
        for k,(a,b) in self.maps['id_counts'].items():out['id_counts/'+k+'/match']=a;out['id_counts/'+k+'/drop']=b
        return out
    def bucket(self,r):
        logical=self.protocol>=4 or self.condition(r)
        return ('id_rl_states',LE32(r['logical_id'])) if logical else ('cidr_rl_states' if cidr(r) else 'rl_states',self.key(r))
    def seed_rate(self):
        for n in ('config_a','config_b'):self.maps[n][LE32(11)]=LE64(1)
        for r in self.installed:
            if r['action']!='rate_limit':continue
            n,k=self.bucket(r)
            self.maps[n][k]=dict(tokens=[0]*self.cpus,last_update_present=[True]*self.cpus)
            self.times[n,k]=[self.now+3_600_000_000_000]*self.cpus
    def take(self,r):
        n,k=self.bucket(r);cpu=self.packet_cpu;capacity=2*r['rate_limit']
        if k not in self.maps[n]:self.maps[n][k]=dict(tokens=[0]*self.cpus,last_update_present=[False]*self.cpus);self.times[n,k]=[0]*self.cpus
        row=self.maps[n][k];stamps=self.times[n,k];last=stamps[cpu]
        if last==0:tokens,last,allowed=capacity-1,self.now,True
        else:
            last=min(last,self.now);added=(self.now-last)*r['rate_limit']//1_000_000_000
            tokens=min(capacity,min(row['tokens'][cpu],capacity)+added)
            if tokens==capacity:last=self.now
            elif added:last+=added*1_000_000_000//r['rate_limit']
            allowed=tokens>=1;tokens-=int(allowed)
        row['tokens'][cpu],stamps[cpu]=tokens,last;row['last_update_present']=[x!=0 for x in stamps]
        return allowed
    def packet(self,name,winner):
        self.now+=1_000_000;before=self.counters();times=copy.deepcopy(self.times);verdict=2
        if winner['RuleID']:
            r=next(r for r in self.installed if r['id']==winner['RuleID']);verdict=1
            if r['action']=='rate_limit':
                if self.take(r):verdict=2
                else:self.maps['stats'][LE32(4)][0]+=1
            if self.protocol>=4 or self.condition(r):
                values=self.maps['id_counts'].setdefault(LE32(r.get('logical_id',0)),[0,0]);values[0]+=1;values[1]+=int(verdict==1)
            else:
                n,k=self.name(r),self.key(r);v=bytearray.fromhex(self.maps[n][k]);a,b=struct.unpack_from('<QQ',v,8);struct.pack_into('<QQ',v,8,a+1,b+int(verdict==1));self.maps[n][k]=v.hex()
        self.maps['stats'][LE32(1 if verdict==1 else 2)][0]+=1
        after=self.counters();delta={k:v-before.get(k,0) for k,v in after.items() if v!=before.get(k,0)}
        changes={n+'/'+k:([a!=b for a,b in zip(times[n,k],v)] if (n,k) in times else [True]*self.cpus) for (n,k),v in self.times.items()}
        return dict(packet=name,verdict=verdict,counter_delta=delta,last_update_changed=changes)
    def run(self,scene,oracle=None):
        records={};inputs={}
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name']
            if step['Method']=='STARTUP_CLEAR_FAILURE':
                self.maps['blacklist'][bytes(40).hex()]=bytes(32).hex();records[case]=dict(startup_refused=True,maps_after_clear=copy.deepcopy(self.maps));inputs[case]=[];continue
            status,body=self.request(step)
            inputs[case]=copy.deepcopy(self.installed)
            rec=dict(installed=dict(count=len(self.installed),rules=sorted(copy.deepcopy(self.installed),key=lambda r:r['id'])),maps_before_packets=copy.deepcopy(self.maps))
            if step['Method']=='RESTART':rec['startup_success']=True
            else:rec.update(status=status,body=response_projection(body))
            packets=[]
            for i,name in enumerate(step['Packets']):
                if oracle is None:continue
                if name=='rate' and 'rate_initial' not in rec:self.seed_rate();rec['rate_initial']=copy.deepcopy(self.maps)
                packets.append(self.packet(name,oracle[case]['P'+str(min(self.protocol,4))][i]))
            rec.update(packets=packets,maps_after_packets=copy.deepcopy(self.maps));records[case]=rec
        return records,inputs

def inputs(scenes):
    out={}
    for scene in scenes:
        a=State(3).run(scene)[1];b=State(4).run(scene)[1]
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name'];out[case]=dict(RulesP3=a[case],RulesP4=b[case],Packets=step['Packets'])
    return out

def authority(scene,path):
    joined='/'.join(map(str,path))
    if 'packets' in path and (scene['Name'].startswith('J9') or path[-1]=='verdict'):return 'J9' if scene['Name'].startswith('J9') else 'I12b'
    if 'rl_states' in joined or 'last_update' in joined or 'rate_initial' in path:return 'I12b'
    if scene['Name'].startswith('I10'):return 'I10'
    if scene['Name'].startswith('I17b'):return 'I17b'
    if path[-1]=='sync_protocol':return 'I9'
    return 'I11b'

def records_and_table(scenes,oracle,cpus,cpu):
    old,new,table={},{},[]
    for scene in scenes:
        a=State(3,cpus,cpu).run(scene,oracle)[0];b=State(4,cpus,cpu).run(scene,oracle)[0];old.update(a);new.update(b)
        for path,x,y in differences(a,b):table.append(dict(case=path[0],field=list(path[1:]),old=x,new=y,authority=authority(scene,path)+' PLAN ④-1 / auth-2 protocol 4 finite projection'))
    return old,new,table

def main():
    p=argparse.ArgumentParser();p.add_argument('--scenarios',type=Path,required=True);p.add_argument('--oracle-input',type=Path);p.add_argument('--oracle',type=Path);p.add_argument('--possible-cpus',type=int,default=1);p.add_argument('--packet-cpu',type=int,default=0);p.add_argument('--output',type=Path)
    a=p.parse_args();scenes=json.loads(a.scenarios.read_text())
    if a.oracle_input:
        v=inputs(scenes);a.oracle_input.write_text(json.dumps(v,indent=2)+'\n');print('CUT54_ORACLE_INPUT cases=%d observed_inputs=0'%len(v));return
    oracle=json.loads(a.oracle.read_text());old,new,table=records_and_table(scenes,oracle,a.possible_cpus,a.packet_cpu)
    for scene in scenes:
        for step in scene['Steps']:
            case=scene['Name']+'/'+step['Name']
            for version in ('P3','P4'):step['Hits'+version]=[bool(v['RuleID']) for v in oracle[case][version]]
    a.scenarios.write_text(json.dumps(scenes,indent=2)+'\n');a.output.write_text(json.dumps(table,indent=2)+'\n')
    print('CUT54_ALLOWED rows=%d scenes=%d steps=%d possible_cpus=%d packet_cpu=%d observations=0'%(len(table),len(scenes),len(old),a.possible_cpus,a.packet_cpu))
if __name__=='__main__':main()
