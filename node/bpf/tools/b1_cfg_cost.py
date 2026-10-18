#!/usr/bin/env python3
"""Bound decoded BPF CFG paths and individual helper/kfunc call counts.

Uses llvm-objdump -dr -l from real ELF, including relocations and inline calls.
LDDW is one decoded instruction / two slots. Numeric iterators admit at most
COMBO_ORDER_LEN non-null results plus one terminal next call. Unknown calls,
missing relocations, edges or unbounded cycles fail. Data correlations between
branches are not solved: these are conservative CFG bounds, not timing or a
bound on helper internals/JIT/cache. Each reported metric is maximized separately.
"""
import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import struct

HELPERS = {1:'map_lookup',2:'map_update',3:'map_delete',5:'ktime_get_ns',8:'get_smp_processor_id',12:'tail_call',51:'redirect_map'}
KF = ('bpf_iter_num_new','bpf_iter_num_next','bpf_iter_num_destroy')
METRICS = ('instructions','slots',*HELPERS.values(),'stats_map_lookup',*KF)
MI,AI,CH,TAIL,EX,CI,RL = 1,2,4,8,16,32,64
ZERO = (0,)*len(METRICS)


def decode(path):
    funcs={};section=None;current=None;line=None;last=None
    for text in path.read_text().splitlines():
        m=re.match(r'Disassembly of section (\S+):',text)
        if m:section=m[1];current=None;continue
        m=re.match(r'([0-9a-f]+) <(\w+)>:',text)
        if m:
            current=m[2];assert current not in funcs
            funcs[current]={'section':section,'start':int(m[1],16)//8,'ops':{}}
            continue
        m=re.match(r'; (.+):([0-9]+)(?: \(discriminator .*)?$',text)
        if m:line=(Path(m[1]).name,int(m[2]));continue
        m=re.match(r'\s*(\d+):\s+((?:[0-9a-f]{2} ){7,15}[0-9a-f]{2})\s+(.+)',text)
        if m:
            assert current,(path,text)
            pc=int(m[1]);raw=bytes.fromhex(m[2]);op,ds,off,imm=struct.unpack('<BBhi',raw[:8])
            assert len(raw)==(16 if op==0x18 else 8)
            last={'op':op,'dst':ds&15,'src':ds>>4,'off':off,'imm':imm,'slots':len(raw)//8,'asm':m[3],'line':line,'reloc':None,'raw':raw}
            funcs[current]['ops'][pc]=last;continue
        m=re.search(r'([0-9a-f]+):\s+R_BPF_64_(32|64)\s+(\S+)',text)
        if m:
            assert last is not None and int(m[1],16)==pc*8
            assert last['reloc'] is None
            last['reloc']=(m[2],m[3])
    starts={(f['section'],f['start']):n for n,f in funcs.items()}
    for name,f in funcs.items():
        assert f['start']==min(f['ops'])
        for pc,i in f['ops'].items():
            op=i['op'];cls=op&7;kind=op&0xf0;nxt=pc+i['slots']
            valid = (op==0x18 or
                     cls in (1,2,3) and op&0xe0 in (0x60,0xc0) or
                     cls in (4,7) and kind in range(0,0xe0,0x10) or
                     cls in (5,6) and kind in range(0,0xe0,0x10))
            assert valid,(name,pc,'unknown opcode',op)
            i['call']=None
            if op==0x85:
                if i['src']==0:
                    assert i['reloc'] is None and i['imm'] in HELPERS,(name,pc,'unknown helper',i)
                    i['call']=HELPERS[i['imm']]
                else:
                    rel=i['reloc']
                    if rel:
                        assert rel[0]=='32'
                        target=rel[1]
                        if target=='.text':target=starts.get(('.text',i['imm']+1))
                    else:
                        target=starts.get((f['section'],pc+i['imm']+1))
                    assert target in funcs or target in KF,(name,pc,'unresolved call',i)
                    i['call']=target
            if cls in (5,6) and kind==0x90:i['edges']=[]
            elif cls in (5,6) and kind!=0x80:
                target=pc+1+i['off'];i['edges']=[target] if kind==0 else [nxt,target]
            else:i['edges']=[nxt]
            assert all(e in f['ops'] for e in i['edges']),(name,pc,'edge escapes function')
    return funcs


def verify_elf(path, funcs):
    raw=path.read_bytes()
    assert raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==247, 'ELF64 little-endian BPF required'
    off=struct.unpack_from('<Q',raw,40)[0];ent,n,strings=struct.unpack_from('<HHH',raw,58)
    assert ent==64
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,off+i*ent) for i in range(n)]
    def data(h):return raw[h[4]:h[4]+h[5]]
    names=data(sections[strings])
    def cstr(blob,start):return blob[start:blob.index(b'\0',start)].decode()
    sections_by_name={cstr(names,h[0]):h for h in sections}
    symbols={};symtabs={}
    for index,h in enumerate(sections):
        if h[1]!=2:continue
        assert h[9]==24 and h[5]%24==0
        strtab=data(sections[h[6]])
        symtabs[index]=[]
        for q in range(h[4],h[4]+h[5],24):
            ni,info,other,sh,value,size=struct.unpack_from('<IBBHQQ',raw,q)
            symbol=cstr(strtab,ni)
            if info&15==3:
                assert 0<sh<len(sections)
                symbol=cstr(names,sections[sh][0])
            symtabs[index].append((symbol,info&15,sh,value))
            if info&15==2 and sh:
                assert symbol not in symbols and value%8==size%8==0
                symbols[symbol]=(cstr(names,sections[sh][0]),value//8,size//8)
    assert set(symbols)==set(funcs),'ELF/disassembly function identity set'
    for name,f in funcs.items():
        sec,start,size=symbols[name]
        assert (sec,start)==(f['section'],f['start'])
        blob=data(sections_by_name[sec]);covered=set()
        for pc,i in f['ops'].items():
            assert blob[pc*8:(pc+i['slots'])*8]==i['raw'],('ELF/disassembly bytes',name,pc)
            covered.update(range(pc,pc+i['slots']))
        assert covered==set(range(start,start+size)),('omitted ELF instructions',name)
    # Authenticate relocation text as well as instruction bytes. Call immediates
    # alone do not identify a callee in a relocatable object.
    decoded={(f['section'],pc*8):i for f in funcs.values() for pc,i in f['ops'].items()}
    starts={(sec,start):name for name,(sec,start,size) in symbols.items()}
    relocations={}
    for h in sections:
        if h[1] not in (4,9):continue  # SHT_RELA / SHT_REL
        assert h[7]<len(sections)
        target_section=sections[h[7]]
        if not target_section[2]&4:continue  # only executable sections
        assert h[1]==9 and h[9]==16 and h[5]%16==0, 'ELF call relocation format'
        assert h[6] in symtabs, 'ELF relocation symbol table'
        sec=cstr(names,target_section[0])
        for q in range(h[4],h[4]+h[5],16):
            offset,info=struct.unpack_from('<QQ',raw,q)
            kind,symid=info&0xffffffff,info>>32
            key=(sec,offset)
            assert key in decoded and key not in relocations, ('ELF relocation location',key)
            assert kind in (1,10) and symid<len(symtabs[h[6]]), ('ELF relocation type/symbol',key)
            symbol,typ,sh,value=symtabs[h[6]][symid]
            expected=('32' if kind==10 else '64',symbol)
            i=decoded[key]
            assert i['reloc']==expected, ('ELF/disassembly relocation',key,i['reloc'],expected)
            relocations[key]=expected
            if kind==10:
                assert i['op']==0x85 and i['src'] in (1,2), ('ELF call relocation instruction',key)
                if sh==0:
                    assert symbol in KF and i['imm']==-1, ('ELF undefined call',key,symbol)
                    target=symbol
                else:
                    assert typ in (2,3) and sh<len(sections) and value%8==0
                    target=starts.get((cstr(names,sections[sh][0]),value//8+i['imm']+1))
                    assert target is not None, ('ELF unresolved call',key,symbol)
                assert i['call']==target, ('ELF/disassembly call target',key,i['call'],target)
            else:
                assert i['op']==0x18, ('ELF data relocation instruction',key)
    assert relocations=={key:i['reloc'] for key,i in decoded.items() if i['reloc'] is not None}, 'ELF/disassembly relocation set'
    return hashlib.sha256(raw).hexdigest()


def add(a,b):return tuple(x+y for x,y in zip(a,b))
def merge(out,mask,v):
    if mask in out:out[mask]=tuple(max(x,y) for x,y in zip(out[mask],v))
    else:out[mask]=v


def walk_cfg(name, function, limit, iterator_guard, statsline, funcs, summary):
    """Postorder DFS with an explicit stack: CFG depth never uses Python's C stack.

    Cache/active keys include the bounded iterator count. An edge to an active
    state is still an unbounded cycle and fails, as in the recursive traversal.
    Calls use per-function summaries (the BPF call graph is acyclic).
    """
    cache, active, frames = {}, set(), {}
    start = (function['start'], 0)
    stack = [(start, False)]
    while stack:
        state, finish = stack.pop()
        if state in cache:
            continue
        pc, iterations = state
        if not finish:
            assert state not in active, ('unbounded CFG cycle', name, pc)
            active.add(state)
            i = function['ops'][pc]
            if i['call'] == 'bpf_iter_num_next':
                iterations += 1
            assert iterations <= limit+1, (name, 'iterator calls exceed bound')
            edges = i['edges']
            if (name, pc) in iterator_guard and iterations == limit+1:
                edges = [pc+1+i['off']] if i['op'] == 0x15 else [pc+1]
            children = [(edge, iterations) for edge in edges]
            frames[state] = (i, children)
            stack.append((state, True))
            stack.extend((child, False) for child in reversed(children))
            continue
        i, children = frames.pop(state)
        cost = list(ZERO); cost[0] = 1; cost[1] = i['slots']
        call, event = i['call'], i['event']
        if call in METRICS:
            cost[METRICS.index(call)] += 1
        if call == 'map_lookup' and i['line'] and i['line'][0] == 'xdrop_main.c' and i['line'][1] in statsline:
            cost[METRICS.index('stats_map_lookup')] += 1
        suffix = {}
        if not children:
            suffix[0] = ZERO
        for child in children:
            for mask, value in cache[child].items():
                merge(suffix, mask, value)
        local = summary(call) if call in funcs else {0: ZERO}
        result = {}
        for lm, lv in local.items():
            for sm, sv in suffix.items():
                merge(result, event|lm|sm, add(tuple(cost), add(lv, sv)))
        # Success transfers control to anomaly; failure continues in main.
        if call == 'tail_call':
            assert name == 'xdp_firewall_main'
            for am, av in summary('xdp_anomaly_verify').items():
                merge(result, event|am, add(tuple(cost), av))
        active.remove(state)
        cache[state] = result
    return cache[start]


def source_hit_anchors(text):
    """Bind each counter/entry anchor to one spelling and one source function.

    Historical programs have one exact and one CIDR row counter per entry.
    B1 adds a shared logical counter and two entry reads; cut54 removes the
    four row counters. Never accept a missing or duplicated full-source anchor.
    Synthetic relocation fixtures have no C function definitions.
    """
    lines = text.splitlines()
    hitlines = {n for n, line in enumerate(lines, 1)
                if line.strip() in ('rule->match_count++;', 'cidr_rule->match_count++;', 'counter->match++;')}
    hitentry = {n for n, line in enumerate(lines, 1) if 'int has_conditions =' in line}
    if 'int xdp_firewall_main(' not in text:
        return hitlines, hitentry

    def exactly_once(spelling):
        found = [n for n, line in enumerate(lines, 1) if line.strip() == spelling]
        assert len(found) == 1, ('hit anchor count', spelling, len(found))
        return found[0]

    logical = 'count_logical_match(' in text
    cut54 = '#define B1_LOOKUP_GENERATION 54' in text
    if logical:
        exactly_once('counter->match++;')
        expected = {exactly_once('int has_conditions = rule->pad2[0] & RULE_HAS_CONDITIONS;'),
                    exactly_once('int has_conditions = cidr_rule->pad2[0] & RULE_HAS_CONDITIONS;')}
        assert hitentry == expected, ('unexpected hit entry anchor', hitentry, expected)
    else:
        assert not hitentry, ('unexpected legacy hit entry', hitentry)
    legacy = hitlines - {n for n, line in enumerate(lines, 1) if line.strip() == 'counter->match++;'}
    assert len(legacy) == (0 if cut54 else 4), ('legacy hit anchor count', len(legacy))
    return hitlines, hitentry


def measure(disassembly,source,header,elf):
    funcs=decode(disassembly);elf_sha=verify_elf(elf,funcs);lines=source.read_text().splitlines()
    order=re.search(r'combo_order\[\]\s*=\s*\{([^}]+)\}',header.read_text())[1]
    limit=len([x for x in order.split(',') if x.strip()]);assert limit==31
    hitlines,hitentry=source_hit_anchors(source.read_text())
    statsline={n for n,l in enumerate(lines,1) if 'bpf_map_lookup_elem(&stats,' in l}
    points=[];iterator_guard={}
    for name,f in funcs.items():
        for pc,i in f['ops'].items():
            event=0
            if i['line'] and i['line'][0]=='xdrop_main.c' and i['line'][1] in hitlines and i['op']&7 in (2,3):
                assert name in ('xdp_firewall_main','xdp_anomaly_verify')
                event=MI if name=='xdp_firewall_main' else AI
            # Knife-three counter allocation can fail: entry still means hit.
            if name=='xdp_firewall_main' and i['line'] and i['line'][0]=='xdrop_main.c' and i['line'][1] in hitentry and i['op']&7==1:
                event|=MI
            # The actual compiled winner byte store (attrs.out at ABI offset 12).
            if name=='cond_match' and i['op']==0x73 and i['off']==12:event|=CH
            if i['call']=='lookup_rule':event|=EX
            if i['call']=='lookup_cidr_rule':event|=CI
            if i['call']=='tail_call':event|=TAIL
            if name=='xdp_firewall_main' and i['call']=='ktime_get_ns':event|=RL
            i['event']=event
            if event:points.append({'function':name,'pc':pc,'event':event,'source_line':i['line']})
            if i['call']=='bpf_iter_num_new':
                prev=f['ops'][pc-1]
                assert prev['op']==0xb7 and prev['dst']==3 and prev['imm']==limit,(name,'iterator bound')
            if i['call']=='bpf_iter_num_next':
                q=pc+1
                while f['ops'][q]['op']==0xb7 and f['ops'][q]['dst']!=0:q+=1
                guard=f['ops'][q]
                assert guard['op'] in (0x15,0x55) and guard['dst']==0 and guard['imm']==0,(name,'iterator null guard')
                iterator_guard[(name,q)]=True
    assert any(p['event']==MI for p in points), 'main hit classification missing'
    if 'xdp_anomaly_verify' in funcs:
        assert any(p['event']==AI for p in points), 'anomaly hit classification missing'
    if 'cond_match' in funcs:assert any(p['event']==CH for p in points)
    active_funcs=set()
    @lru_cache(None)
    def summary(name):
        assert name not in active_funcs,('recursive BPF call',name)
        active_funcs.add(name);f=funcs[name]
        result=walk_cfg(name,f,limit,iterator_guard,statsline,funcs,summary)
        active_funcs.remove(name);return result
    paths=summary('xdp_firewall_main')
    predicates={
        'no_anomaly_rules':lambda m:not m&TAIL,
        'ordinary_hit':lambda m:bool(m&MI) and not m&(CH|TAIL),
        'all_miss':lambda m:(m&(EX|CI))==(EX|CI) and not m&(MI|AI|CH),
        'condition_hit':lambda m:bool(m&MI) and bool(m&CH) and not m&TAIL,
        'condition_rate_limit_hit':lambda m:(m&(MI|CH|RL))==(MI|CH|RL) and not m&TAIL,
    }
    rows={}
    for name,valid in predicates.items():
        vals=[v for m,v in paths.items() if valid(m)]
        rows[name]=dict(zip(METRICS,map(max,zip(*vals)))) if vals else None
    # Main plus optional anomaly is charged; gate precedes all classes equally
    # and is outside these main-pipeline path categories.
    return {'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'elf_sha256':elf_sha,'combo_order_len':limit,'metrics':METRICS,'paths':rows,'classification_points':points,
            'functions':{n:{'decoded_instructions':len(f['ops']),'bounded_iterator':any(i['call']=='bpf_iter_num_new' for i in f['ops'].values())} for n,f in funcs.items()},
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'disassembly_sha256':hashlib.sha256(disassembly.read_bytes()).hexdigest(),
            'scope':'main pipeline and successful anomaly tail target; gate excluded equally; independent maxima per metric; branch data correlations not solved; stats_map_lookup is a subset of map_lookup',
            'limits':'CFG abstraction upper bounds in instructions and call counts only; excludes helper/kfunc bodies, JIT and cache; not time or total runtime cost'}


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--disassembly',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--header',type=Path,required=True);ap.add_argument('--elf',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    data=measure(a.disassembly,a.source,a.header,a.elf);a.output.write_text(json.dumps(data,indent=2)+'\n')
    for name,row in data['paths'].items():print('B1_CFG_COST',name,json.dumps(row,sort_keys=True))
