"""Offline ELF relocation controls; these do not claim kernel acceptance."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import b1_cfg_cost as cost


def fixture(W, hit_entry=False, include_anomaly=True):
    def op(code,dst=0,src=0,off=0,imm=0):return struct.pack('<BBhi',code,dst|(src<<4),off,imm)
    # main: lookup boundary; match-counter store; relocated expensive callee; exit.
    funcs=[('xdp_firewall_main',[op(0x85,src=1,imm=-1),op(0x71 if hit_entry else 0x7b,dst=1,src=2),op(0x85,src=1,imm=-1),op(0x95)]),
           ('xdp_anomaly_verify',[op(0x7b,dst=1,src=2),op(0x95)]),
           ('lookup_rule',[op(0x95)]),
           ('cond_match',[op(0x73,dst=1,src=2,off=12)]+[op(0x85,imm=1) for _ in range(20)]+[op(0x95)]),
           ('xdrop_launder',[op(0x95)])]
    if not include_anomaly:
        funcs=[(name,ops) for name,ops in funcs if name!='xdp_anomaly_verify']
    starts={};blob=b''
    for name,ops in funcs:starts[name]=len(blob)//8;blob+=b''.join(ops)
    strtab=b'\0';names={}
    for name,_ in funcs:names[name]=len(strtab);strtab+=name.encode()+b'\0'
    symtab=bytes(24);symids={}
    for n,(name,ops) in enumerate(funcs,1):
        symids[name]=n;symtab+=struct.pack('<IBBHQQ',names[name],0x12,0,1,starts[name]*8,len(ops)*8)
    # Actual ELF relocations identify lookup_rule and cond_match, regardless of text.
    rel=struct.pack('<QQ',0,(symids['lookup_rule']<<32)|10)+struct.pack('<QQ',16,(symids['cond_match']<<32)|10)
    shstr=b'\0.text\0.strtab\0.symtab\0.rel.text\0.shstrtab\0'
    sections=[('',0,b'',0,0,0,0),('.text',1,blob,0,0,8,0),('.strtab',3,strtab,0,0,1,0),
              ('.symtab',2,symtab,2,1,8,24),('.rel.text',9,rel,3,1,8,16),('.shstrtab',3,shstr,0,0,1,0)]
    raw=bytearray(64);headers=[]
    for name,kind,data,link,info,align,entsize in sections:
        while align and len(raw)%align:raw+=b'\0'
        offset=len(raw);raw+=data
        headers.append(struct.pack('<IIQQQQIIQQ',shstr.index(name.encode()+b'\0') if name else 0,kind,6 if kind==1 else 0,0,offset,len(data),link,info,align,entsize))
    while len(raw)%8:raw+=b'\0'
    shoff=len(raw);raw+=b''.join(headers)
    raw[:64]=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,247,1,0,0,shoff,0,64,0,0,64,len(sections),5)
    elf=W/'fixture.elf';elf.write_bytes(raw)
    source=W/'xdrop_main.c';source.write_text(('int has_conditions = rule->pad2[0];' if hit_entry else 'rule->match_count++;')+'\nbpf_map_lookup_elem(&stats, &idx);\n/* other instruction */\nrule->match_count++;\n')
    header=Path(__file__).resolve().parents[1]/'combo_masks.h'
    lines=['Disassembly of section .text:']
    for name,ops in funcs:
        pc=starts[name];lines.append(f'{pc*8:016x} <{name}>:')
        source_line='4' if hit_entry and name=='xdp_anomaly_verify' else '1' if name in ('xdp_firewall_main','xdp_anomaly_verify') else '3'
        lines.append('; /synthetic/xdrop_main.c:'+source_line)
        for i,rawop in enumerate(ops):
            if name=='cond_match' and i==1:lines.append('; /synthetic/xdrop_main.c:2')
            lines.append(f' {pc}: '+rawop.hex(' ')+' synthetic')
            if name=='xdp_firewall_main' and i in (0,2):
                target='lookup_rule' if i==0 else 'cond_match'
                lines.append(f' {pc*8:016x}: R_BPF_64_32 {target}')
            pc+=1
    text='\n'.join(lines)+'\n'
    original=W/'original.dis';original.write_text(text)
    return original,source,header,elf


class ELFRelocationTests(unittest.TestCase):
    def test_hit_entry_survives_missing_counter(self):
        with tempfile.TemporaryDirectory(prefix='b1-cfg-entry-') as tmp:
            result=cost.measure(*fixture(Path(tmp), hit_entry=True))
            self.assertEqual(result['paths']['condition_hit']['instructions'],27)
            self.assertTrue(any(p['event']&cost.MI for p in result['classification_points']))

    def test_original_and_forged_relocation(self):
        with tempfile.TemporaryDirectory(prefix='b1-cfg-') as tmp:
            dis,source,header,elf=fixture(Path(tmp))
            original=elf.read_bytes()
            positive=cost.measure(dis,source,header,elf)
            self.assertEqual(positive['paths']['condition_hit']['map_lookup'],20)
            self.assertEqual(positive['paths']['condition_hit']['instructions'],27)
            text=dis.read_text()
            dis.write_text(text.replace('R_BPF_64_32 cond_match','R_BPF_64_32 xdrop_launder'))
            with self.assertRaisesRegex(AssertionError,'ELF/disassembly relocation'):
                cost.measure(dis,source,header,elf)
            self.assertEqual(elf.read_bytes(),original)
            print('B1_CFG_RELOC positive_instructions=27 positive_lookups=20 forged_target_rejected=1 ELF_bytes_unchanged=1')

    def test_location_type_missing_and_resolution(self):
        with tempfile.TemporaryDirectory(prefix='b1-cfg-') as tmp:
            dis,source,header,elf=fixture(Path(tmp))
            good=cost.decode(dis)
            for label,mutate in [
                ('type',lambda x:x['xdp_firewall_main']['ops'][2].update(reloc=('64','cond_match'))),
                ('missing',lambda x:x['xdp_firewall_main']['ops'][2].update(reloc=None)),
                ('invented',lambda x:x['xdp_anomaly_verify']['ops'][4].update(reloc=('32','cond_match'))),
                ('resolution',lambda x:x['xdp_firewall_main']['ops'][2].update(call='xdrop_launder')),
            ]:
                with self.subTest(label=label):
                    bad=copy.deepcopy(good);mutate(bad)
                    with self.assertRaisesRegex(AssertionError,'ELF/disassembly'):
                        cost.verify_elf(elf,bad)
            dis.write_text(dis.read_text().replace('0000000000000010: R_BPF','0000000000000011: R_BPF'))
            with self.assertRaises(AssertionError):cost.decode(dis)
            print('B1_CFG_RELOC controls_rejected=5/5')




class IterativeCFGTests(unittest.TestCase):
    def op(self, edges, call=None, event=0):
        return {'edges':edges, 'call':call, 'event':event, 'slots':1,
                'line':None, 'op':0x15, 'off':1}

    def run_cfg(self, ops, guards=None):
        return cost.walk_cfg('test', {'start':0, 'ops':ops}, 31,
                             guards or {}, set(), {}, lambda _: {0:cost.ZERO})

    def test_deep_chain_without_recursion_limit_change(self):
        import sys
        before=sys.getrecursionlimit()
        ops={i:self.op([i+1] if i<19999 else []) for i in range(20000)}
        result=self.run_cfg(ops)
        self.assertEqual(result[0][:2], (20000,20000))
        self.assertEqual(sys.getrecursionlimit(), before)
        print('B1_CFG_ITERATIVE chain_instructions=20000 recursion_limit_unchanged=1')

    def test_diamond_independent_metric_maxima(self):
        ops={0:self.op([1,2]),1:self.op([3], 'map_lookup'),
             2:self.op([4], 'map_update'),4:self.op([3], 'map_update'),3:self.op([])}
        result=dict(zip(cost.METRICS,self.run_cfg(ops)[0]))
        self.assertEqual((result['instructions'],result['map_lookup'],result['map_update']), (4,1,2))

    def test_iterator_bound_and_cycle_rejection(self):
        ops={0:self.op([1], 'bpf_iter_num_next'), 1:self.op([2,3]),
             2:self.op([0], 'map_lookup'), 3:self.op([])}
        ops[1]['off']=1
        result=dict(zip(cost.METRICS,self.run_cfg(ops,{('test',1):True})[0]))
        self.assertEqual((result['instructions'],result['bpf_iter_num_next'],result['map_lookup']), (96,32,31))
        with self.assertRaisesRegex(AssertionError,'unbounded CFG cycle'):
            self.run_cfg({0:self.op([0])})
        with self.assertRaisesRegex(AssertionError,'iterator calls exceed bound'):
            self.run_cfg({0:self.op([0], 'bpf_iter_num_next')})

if __name__=='__main__':unittest.main()
