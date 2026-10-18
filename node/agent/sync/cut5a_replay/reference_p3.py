#!/usr/bin/env python3
"""Finite 5-3 allow-table specification, independent of replay observations.

The model covers only the explicitly named p3 scenarios. It models wire bytes,
HTTP projections and packet effects from the ABI/PLAN. It never reads an actual
old/new replay file. CPU topology is an explicit environment parameter needed
to spell out every element of newly present per-CPU rate-state rows.
"""
import argparse
import copy
import ipaddress
import json
import struct
from pathlib import Path
from compare import differences
from generate_p3_scenarios import build

HERE = Path(__file__).parent
LE32 = lambda x: struct.pack("<I", x).hex()
LE64 = lambda x: struct.pack("<Q", x).hex()
EXPR = ("ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len")
RULE_MAPS = ("blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b")
COND_MAPS = ("cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b")


def response_projection(value):
    # cut5ReplayHTTP applies cut5ReplayNormalize after decoding the response.
    # Production rejects in request order; recorded ID-bearing arrays are sorted.
    if isinstance(value, dict):
        return {k: response_projection(v) for k, v in value.items()}
    if isinstance(value, list):
        values = [response_projection(v) for v in value]
        if values and isinstance(values[0], dict) and "id" in values[0]:
            values.sort(key=lambda v: v["id"])
        return values
    return value


def spans(value):
    if value is None:
        return None
    out = []
    for piece in value.replace(" ", "").split(","):
        ends = piece.split("-")
        out.append((int(ends[0]), int(ends[-1])))
    out.sort()
    merged = []
    for lo, hi in out:
        if merged and lo <= merged[-1][1]+1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def canonical(r):
    r = copy.deepcopy(r)
    for key in EXPR:
        if key in r and key != "fragment":
            r[key] = ",".join(str(a) if a == b else "%d-%d" % (a,b) for a,b in spans(r[key]))
    if "tcp_flags" in r:
        r["tcp_flags"] = ",".join(sorted(r["tcp_flags"].split(",")))
    return {k:v for k,v in r.items() if v not in (None, "", 0)}


def flag_pair(r):
    mask = value = 0
    names = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
    for word in r.get("tcp_flags", "").split(","):
        if not word:
            continue
        bit = 1 << names.index(word.lstrip("!"))
        mask |= bit
        if not word.startswith("!"):
            value |= bit
    return mask, value


def is_cidr(r):
    return "src_cidr" in r


def key(r):
    if is_cidr(r):
        return (struct.pack("<II",1,0)+struct.pack(">HH",r.get("src_port",0),r.get("dst_port",0))+bytes([6,0,0,0])).hex()
    src = bytes(10)+bytes.fromhex("ffff")+ipaddress.ip_address(r["src_ip"]).packed
    proto = {"tcp":6,"icmp":1}[r["protocol"]]
    return (src+bytes(16)+struct.pack(">HH",r.get("src_port",0),r.get("dst_port",0))+bytes([proto,0,0,0])).hex()


def identity(r):
    return dict(kind="cidr" if is_cidr(r) else "exact", **({"src_cidr":r["src_cidr"]} if is_cidr(r) else {"src_ip":r["src_ip"]}), src_port=r.get("src_port",0), dst_port=r.get("dst_port",0), protocol=r["protocol"])


def extended(r):
    return any(k in r for k in EXPR+("tcp_flags","pkt_len_min","pkt_len_max","match_anomaly"))


def strictness(r):
    return sum(k in r for k in EXPR+("tcp_flags","match_anomaly")) + int("pkt_len_min" in r or "pkt_len_max" in r)


def condition_wire(rules):
    # Six nibble tables, four fragment bytes, eight length spans, then metadata.
    rules = sorted(rules,key=lambda r:(-strictness(r),r["logical_id"]))
    b = bytearray(844)
    for i,r in enumerate(rules):
        bit = 1 << i
        mask, value = flag_pair(r)
        for table,(field,maximum) in enumerate((("ttl",255),("dscp",63),("tcp_flags",255),("icmp_type",255),("icmp_code",255),("match_anomaly",15))):
            domain = spans(r.get(field)) if table in (0,1,3,4) else None
            for v in range(maximum+1):
                allowed = domain is None or any(lo<=v<=hi for lo,hi in domain)
                if table == 2 and mask:
                    allowed = v&mask == value
                if table == 5 and r.get(field):
                    allowed = bool(v&r[field])
                if allowed:
                    b[table*128+v//2] |= bit << ((v&1)*4)
        fragment = {"nofrag":{0,4},"first":{2,6},"middle":{3,7},"last":{1,5}}
        for v in range(8):
            if "fragment" not in r or v in fragment[r["fragment"]]:
                b[768+v//2] |= bit << ((v&1)*4)
        lengths = spans(r.get("pkt_len")) or [(r.get("pkt_len_min",0),r.get("pkt_len_max",0) or 65535)]
        assert len(lengths)<=2
        lengths += [(1,0)]*(2-len(lengths))
        for j,(lo,hi) in enumerate(lengths):
            struct.pack_into("<HH",b,772+i*8+j*4,lo,hi)
        b[804+i] = 2 if r["action"]=="rate_limit" else 1
        struct.pack_into("<I",b,808+i*4,r.get("rate_limit",0) if r["action"]=="rate_limit" else 0)
        struct.pack_into("<I",b,824+i*4,r["logical_id"])
        b[840] |= bit
        if "icmp_type" in r or "icmp_code" in r:
            b[841] |= bit
        if mask:
            b[842] |= bit
    return b.hex()


def rule_wire(r, flag=False, counts=(0,0)):
    mask,value = flag_pair(r)
    return struct.pack("<BBBBIQQHHBBBB",2 if r["action"]=="rate_limit" else 1,0 if flag else mask,0 if flag else value,0 if flag else r.get("match_anomaly",0),r.get("rate_limit",0),*counts,0 if flag else r.get("pkt_len_min",0),0 if flag else r.get("pkt_len_max",0),int(flag),0,0,0).hex()


class State:
    def __init__(self, protocol, cpus, packet_cpu):
        self.protocol, self.cpus, self.packet_cpu = protocol, cpus, packet_cpu
        self.rule_slot = self.config_slot = 0
        self.maps = {n:{} for n in RULE_MAPS+COND_MAPS+("sv4_cidr_trie","dv4_cidr_trie","sv6_cidr_trie","dv6_cidr_trie","rl_states","cidr_rl_states","id_counts","id_rl_states")}
        for n in ("config_a","config_b"):
            self.maps[n] = {LE32(i):LE64(0) for i in range(12)}
        self.maps["active_config"] = {LE32(0):LE64(0)}
        self.maps["stats"] = {LE32(i):[0] for i in range(5)}
        self.installed, self.groups = [], []
        self.no_tail = False
        # Only timestamp relations are exported. These finite witnesses run
        # inside the zero-refill interval, with each packet on packet_cpu.
        self.now_ns = 10_000_000_000
        self.rate_times = {}

    def name(self, cidr=False, slot=None, condition=False):
        slot = self.rule_slot if slot is None else slot
        return (COND_MAPS if condition else RULE_MAPS)[int(cidr)*2+slot]

    def reject(self, code, message, **extra):
        return 409, dict(code=code,error=message,withdrawal_pending=False,**extra)

    def grouped(self, rules):
        groups={}
        for r in rules:
            groups.setdefault((is_cidr(r),key(r)),[]).append(r)
        return list(groups.values())

    def full(self, rules, fault):
        rules=copy.deepcopy(rules)
        if fault=="zero_logical_id":
            rules[0]["logical_id"]=0
        raw_groups=self.grouped(rules)
        if self.protocol==3:
            for group in raw_groups:
                reason=None
                if any(r["logical_id"]==0 for r in group):
                    reason="missing/duplicate logical_id 0"
                if len(group)>4:
                    reason="physical candidates %d exceed 4; occupying rule IDs: %s" % (len(group),",".join(sorted(r["id"] for r in group)))
                if reason:
                    return self.reject("condition_group_invalid","condition group invalid; batch not published",key=identity(group[0]),conflicts=[dict(id=r["id"],reason=reason) for r in group],added=0,failed=1)
            if fault=="capacity_one" and len({r["logical_id"] for r in self.installed+rules})>1:
                return self.reject("table_full","logical state capacity 2 exceeds 1; batch not published",added=0,failed=1)
        shadow=1-self.rule_slot
        for c in (False,True):
            self.maps[self.name(c,shadow)]={}
            self.maps[self.name(c,shadow,True)]={}
        accepted,rejected=[],[]
        seen={}
        for raw in rules:
            if self.protocol==2:
                reason=None
                for field in EXPR:
                    if field in raw:
                        reason="condition field %s is not supported yet" % field
                        break
                if reason is None and raw.get("match_anomaly",0)>3:
                    reason="invalid match_anomaly bits: 0x%x (valid: 0x3)" % raw["match_anomaly"]
                if reason:
                    rejected.append(dict(id=raw["id"],reason=reason));continue
                k=(is_cidr(raw),key(raw))
                if k in seen:
                    first=seen[k]
                    return self.reject("duplicate_key",'duplicate key between rule ID "%s" and rule ID "%s"; batch not published' % (first["id"],raw["id"]),conflicts=[dict(id=first["id"]),dict(id=raw["id"])],added=len(accepted),failed=len(rejected)+1)
                seen[k]=raw
                # Before an abort, the already written shadow row remains.
                self.maps[self.name(is_cidr(raw),shadow)][key(raw)]=rule_wire(raw)
            accepted.append(canonical(raw))
        groups=self.grouped(accepted)
        for group in groups:
            cond=self.protocol==3 and (len(group)>1 or extended(group[0]))
            candidate=sorted(group,key=lambda r:(-strictness(r),r.get("logical_id",0)))[0] if cond else group[0]
            self.maps[self.name(is_cidr(candidate),shadow)][key(candidate)]=rule_wire(candidate,cond)
            if cond:
                self.maps[self.name(is_cidr(candidate),shadow,True)][key(candidate)]=condition_wire(group)
        config=copy.deepcopy(self.maps[("config_a","config_b")[self.config_slot]])
        for c,count_slot,bitmap_slot in ((False,0,2),(True,6,7)):
            gs=[g for g in groups if is_cidr(g[0])==c]
            config[LE32(count_slot)]=LE64(len(gs))
            bitmap=0
            for g in gs:
                bitmap |= 1 << (14 if g[0].get("dst_port") else 9)
            config[LE32(bitmap_slot)]=LE64(bitmap)
        config[LE32(9)]=LE64(shadow)
        config[LE32(10)]=LE64(sum(bool(r.get("match_anomaly")) for r in accepted) if self.protocol==2 else 0)
        self.config_slot=1-self.config_slot
        self.maps[("config_a","config_b")[self.config_slot]]=config
        self.maps["active_config"][LE32(0)]=LE64(self.config_slot)
        self.rule_slot=shadow
        for c in (False,True):
            self.maps[self.name(c,1-shadow)]={}
            self.maps[self.name(c,1-shadow,True)]={}
        self.maps["sv4_cidr_trie"]={}
        if any(is_cidr(r) for r in accepted):
            self.maps["sv4_cidr_trie"]["18000000c0000200"]=LE32(1)
        # Full sync retains legacy tuple buckets on both trees. A moved key
        # creates a separate bucket; its old bucket remains until a later path
        # deletes it. Logical state alone is reconciled here.
        valid={LE32(r["logical_id"]) for r in accepted if r.get("logical_id")}
        for n in ("id_counts","id_rl_states"):
            self.maps[n]={k:v for k,v in self.maps[n].items() if k in valid}
        self.rate_times = {mk: v for mk, v in self.rate_times.items()
                           if mk[0] != "id_rl_states" or mk[1] in valid}
        self.installed,self.groups=accepted,groups
        return 200,dict(success=True,added=len(accepted),failed=len(rejected),rules=sum(not is_cidr(r) for r in accepted),cidr_rules=sum(is_cidr(r) for r in accepted),rejected=rejected,withdrawal_pending=False)

    def request(self, step):
        if step.get("Fault")=="rt_no_tail":
            self.no_tail=True
        if step["Method"]=="GET":
            return 200,dict(sync_protocol=self.protocol,name="XDrop Agent",version="2.6.1",status="running",features=["ipv4","ipv6","rate_limit","decoder_sugar","anomaly_match"])
        if step["Path"]=="/api/v1/sync/atomic":
            return self.full(step["Body"]["rules"],step.get("Fault",""))
        r=canonical(step["Body"])
        if self.protocol==3 and extended(r):
            return self.reject("condition_group_required","condition five-tuple requires a whole-group write",key=identity(r))
        if step.get("Fault")=="active_config_lookup":
            if self.protocol==3:
                return 500,dict(code="internal_error",error="config publish failed",withdrawal_pending=False)
            self.installed=[r];self.groups=[[r]]
            self.maps["blacklist"][key(r)]=rule_wire(r)
            self.maps["config_b"][LE32(0)]=LE64(1)
            self.maps["config_b"][LE32(2)]=LE64(1<<9)
            self.config_slot=1
            self.maps["active_config"][LE32(0)]=LE64(1)
            return 200,dict(success=True,rule_id=r["id"],message="Rule added",code="success",withdrawal_pending=False)
        assert r in self.installed
        return 200,dict(success=True,rule_id=r["id"],code="already_exists",withdrawal_pending=False)

    def counters(self):
        out={}
        for name in RULE_MAPS:
            for k,v in self.maps[name].items():
                a,b=struct.unpack_from("<QQ",bytes.fromhex(v),8)
                out[name+"/"+k+"/match"]=a;out[name+"/"+k+"/drop"]=b
        for k,(a,b) in self.maps["id_counts"].items():
            out["id_counts/"+k+"/match"]=a;out["id_counts/"+k+"/drop"]=b
        return out

    def rate_initial(self):
        for name in ("config_a","config_b"):
            self.maps[name][LE32(11)]=LE64(1)
        for g in self.groups:
            for r in g:
                if r["action"]!="rate_limit":continue
                cond=self.protocol==3 and (len(g)>1 or extended(r))
                name="id_rl_states" if cond else ("cidr_rl_states" if is_cidr(r) else "rl_states")
                k=LE32(r["logical_id"]) if cond else key(r)
                self.maps[name][k]=dict(tokens=[0]*self.cpus,last_update_present=[True]*self.cpus)
                # cut5ReplayRateInitial sets every possible CPU to now + 1 hour.
                self.rate_times[name,k]=[self.now_ns+3_600_000_000_000]*self.cpus

    def rate_take(self, table, k, rate):
        # rate_limit_capacity/take: ceil(2R/d), then consume one token. Unlike
        # presence, a future timestamp changes when clamped even on a drop.
        divisor = int.from_bytes(bytes.fromhex(
            self.maps[("config_a", "config_b")[self.config_slot]][LE32(11)]), "little")
        if divisor <= 0:
            raise ValueError("rate witness must explicitly configure its divisor")
        divisor = min(divisor, 4096)
        capacity = (2*rate+divisor-1)//divisor
        if k not in self.maps[table]:
            self.maps[table][k] = dict(tokens=[0]*self.cpus, last_update_present=[False]*self.cpus)
            self.rate_times[table,k] = [0]*self.cpus
        row = self.maps[table][k]
        stamps = self.rate_times[table,k]
        cpu = self.packet_cpu
        last = stamps[cpu]
        if last == 0:
            tokens, last, allowed = capacity-1, self.now_ns, True
        else:
            last = min(last, self.now_ns)
            elapsed = min(self.now_ns-last, (capacity*divisor*1_000_000_000+rate-1)//rate)
            added = elapsed*rate//(divisor*1_000_000_000)
            tokens = min(capacity, min(row["tokens"][cpu], capacity)+added)
            if tokens == capacity:
                last = self.now_ns
            elif added:
                last += (added*divisor*1_000_000_000+rate-1)//rate
            allowed = tokens >= 1
            tokens -= int(allowed)
        row["tokens"][cpu], stamps[cpu] = tokens, last
        row["last_update_present"] = [stamp != 0 for stamp in stamps]
        return allowed

    def packet(self,name):
        self.now_ns += 1_000_000
        src="203.0.113.1" if name=="miss" else "192.0.2.1"
        proto="icmp" if name=="icmp_zero" else "tcp"
        flags=16 if name=="ack" else 2
        anomaly={"invalid_tcp":2,"length_mismatch":4,"offset_one":8,"bad_fragment":1}.get(name,0)
        length=400 if name=="length400" else 60 if name=="length_mismatch" else 40
        nonfirst=name=="offset_one"
        before=self.counters()
        before_rate=copy.deepcopy(self.rate_times)
        matches=[]
        for g in self.groups:
            for r in g:
                if (is_cidr(r) and ipaddress.ip_address(src) not in ipaddress.ip_network(r["src_cidr"])) or (not is_cidr(r) and src!=r["src_ip"]) or r["protocol"]!=proto:continue
                mask,value=flag_pair(r)
                if mask and (nonfirst or flags&mask!=value):continue
                if r.get("match_anomaly",0) and not (anomaly&r["match_anomaly"]):continue
                if self.protocol==2 and self.no_tail and r.get("match_anomaly"):continue
                if not (r.get("pkt_len_min",0)<=length<=(r.get("pkt_len_max",0) or 65535)):continue
                vals={"ttl":64,"dscp":0,"icmp_type":0,"icmp_code":0,"pkt_len":length}
                if any(k in r and not any(a<=vals[k]<=b for a,b in spans(r[k])) for k in vals):continue
                if "fragment" in r and nonfirst:continue
                stage=(2 if r.get("match_anomaly") else 0)+int(is_cidr(r)) if self.protocol==2 else int(is_cidr(r))
                matches.append((stage,-strictness(r) if self.protocol==3 else 0,r.get("logical_id",0),r,g))
        verdict=2
        if matches:
            _,_,_,r,g=min(matches,key=lambda v:v[:3])
            cond=self.protocol==3 and (len(g)>1 or extended(r))
            verdict=1
            if r["action"]=="rate_limit":
                table="id_rl_states" if cond else ("cidr_rl_states" if is_cidr(r) else "rl_states")
                k=LE32(r["logical_id"]) if cond else key(r)
                if self.rate_take(table, k, r["rate_limit"]):
                    verdict=2
                else:
                    self.maps["stats"][LE32(4)][0]+=1
            if cond:
                c=self.maps["id_counts"].setdefault(LE32(r["logical_id"]),[0,0])
                c[0]+=1;c[1]+=int(verdict==1)
            else:
                m=self.name(is_cidr(r));k=key(r)
                v=bytearray.fromhex(self.maps[m][k]);a,b=struct.unpack_from("<QQ",v,8)
                struct.pack_into("<QQ",v,8,a+1,b+int(verdict==1));self.maps[m][k]=v.hex()
        self.maps["stats"][LE32(1 if verdict==1 else 2)][0]+=1
        after=self.counters()
        delta={k:v-before.get(k,0) for k,v in after.items() if v!=before.get(k,0)}
        changes={}
        for m in ("rl_states","cidr_rl_states","id_rl_states"):
            for k,v in self.maps[m].items():
                # The driver records presence as a change for every CPU when
                # the entire row was absent, including newly present zeroes.
                stamps = self.rate_times[m,k]
                changes[m+"/"+k]=[a != b for a,b in zip(before_rate[m,k],stamps)] if (m,k) in before_rate else [True]*self.cpus
        return dict(packet=name,verdict=verdict,counter_delta=delta,last_update_changed=changes)

    def run(self,scene):
        records={}
        for step in scene["Steps"]:
            case=scene["Name"]+"/"+step["Name"]
            if step["Method"]=="STARTUP_CLEAR_FAILURE":
                self.maps["blacklist"][bytes(40).hex()]=bytes(32).hex()
                records[case]=dict(startup_refused=self.protocol==3,maps_after_clear=copy.deepcopy(self.maps));continue
            status,body=self.request(step)
            body=response_projection(body)
            rec=dict(status=status,body=body,installed=dict(count=len(self.installed),rules=sorted(self.installed,key=lambda r:r["id"])),maps_before_packets=copy.deepcopy(self.maps))
            packets=[]
            for i,name in enumerate(step["Packets"]):
                if name=="rate" and "rate_initial" not in rec:
                    self.rate_initial();rec["rate_initial"]=copy.deepcopy(self.maps)
                packets.append(self.packet(name))
            rec["packets"]=packets;rec["maps_after_packets"]=copy.deepcopy(self.maps)
            records[case]=rec
        return records


def allow_table(cpus,packet_cpu):
    if not 0<=packet_cpu<cpus:raise ValueError("packet CPU outside possible topology")
    table=[]
    for scene in build():
        if scene["Authority"]=="unchanged":continue
        old=State(2,cpus,packet_cpu).run(scene)
        new=State(3,cpus,packet_cpu).run(scene)
        for path,a,b in differences(old,new):
            authority=scene["Authority"]
            if scene["Name"].startswith("I7_legacy_") and path[0].endswith("/full"):
                authority="I11a"
            table.append(dict(case=path[0],field=list(path[1:]),old=a,new=b,authority=authority+" PLAN ④-1 explicit 5-3 projection"))
    return table


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--possible-cpus",type=int,required=True)
    p.add_argument("--packet-cpu",type=int,required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    table=allow_table(args.possible_cpus,args.packet_cpu)
    Path(args.output).write_text(json.dumps(table,indent=2)+"\n")
    print("CUT53_ALLOWED rows=%d possible_cpus=%d packet_cpu=%d observed_replay_inputs=0" % (len(table),args.possible_cpus,args.packet_cpu))
