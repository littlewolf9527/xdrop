#!/usr/bin/env python3
"""Portable frame selfcheck and function-scoped mutation anchor checks."""
import argparse
import contextlib
import copy
import difflib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace

MUTATIONS = {
    'M1': ('node/bpf/xdrop_gate.c', 'should_filter', 'return ingress_ifindex == filter_ifindex;',
           'return ingress_ifindex == filter_ifindex;', 'return 1;'),
    'M3': ('node/bpf/xdrop_main.c', 'xdp_firewall_main', '// Default: pass/redirect',
           '// Default: pass/redirect\n  stats_inc(STATS_PASSED_PACKETS);\n  stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);\n  if (fast_forward)',
           '// Default: pass/redirect\n  stats_inc(STATS_PASSED_PACKETS);\n  stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);\n  if (0)'),
    'M4': ('node/agent/main.go', 'configureFastForward', 'case "inbound":',
           'case "inbound":\n\t\tfilterIdx = uint32(inboundIdx)',
           'case "inbound":\n\t\tfilterIdx = uint32(outboundIdx)'),
    'M5': ('node/agent/api/commit.go', 'writeCommitConfig', 'var exactBitmap, cidrBitmap, exactCount, cidrCount uint64',
           '\tvar exactBitmap, cidrBitmap, exactCount, cidrCount uint64',
           '\tif err := shadow.Update(uint32(ConfigFastForwardEnabled), uint64(0), ebpf.UpdateExist); err != nil {\n\t\treturn err\n\t}\n\tvar exactBitmap, cidrBitmap, exactCount, cidrCount uint64'),
    'M6': ('node/agent/api/sync.go', 'DoAtomicSync', '// 3b. Overwrite dynamic rule fields in shadow config',
           '\t// 3b. Overwrite dynamic rule fields in shadow config',
           '\tif err := shadowConf.Update(uint32(ConfigFilterIfindex), uint64(0), ebpf.UpdateExist); err != nil {\n\t\treturn abort(err)\n\t}\n\t// 3b. Overwrite dynamic rule fields in shadow config'),
    'M7': ('node/agent/api/config.go', 'publishConfigUpdateForWLSync', '// Step 2: Overwrite only the 3 whitelist-owned slots',
           '\t// Step 2: Overwrite only the 3 whitelist-owned slots',
           '\tif err := shadow.Update(uint32(ConfigFastForwardEnabled), uint64(0), ebpf.UpdateExist); err != nil {\n\t\treturn err\n\t}\n\t// Step 2: Overwrite only the 3 whitelist-owned slots'),
}


def anchors(source, dest=None):
    extra = {
      'N2': ('node/agent/main.go','restoreFFInterfaces','} else if state.Attached != 0 {','} else if state.Attached != 0 {','} else if false && state.Attached != 0 {'),
      'N4': ('node/agent/main.go','setupDevmap','for _, key := range stale {','if err := devmap.Delete(key); err != nil {','_ = key\n\t\tif err := error(nil); err != nil {'),
      'N5': ('node/agent/main.go','main','} else if err := clearFastForwardSlots(configA, configB); err != nil {','} else if err := clearFastForwardSlots(configA, configB); err != nil {','} else if err := error(nil); err != nil {'),
    }
    for name, (file, function, anchor, old, new) in dict(MUTATIONS, **extra).items():
        text = (source / file).read_text()
        match = re.search(r'^(?:func |(?:static )?(?:INLINE )?int )[^\n]*\b' + function + r'\([^\n]*', text, re.M)
        assert match, (name, 'function missing')
        end = text.index('\n}', match.start()) + 2
        body = text[match.start():end]
        result = subprocess.run(['/usr/bin/grep', '-F', '-c', '--', anchor], input=body, text=True, capture_output=True)
        assert result.returncode == 0 and result.stdout.strip() == '1', (name, 'anchor not unique')
        assert old in body
        changed = text[:match.start()] + body.replace(old, new, 1) + text[end:]
        patch = ''.join(difflib.unified_diff(text.splitlines(True), changed.splitlines(True), fromfile='a/'+file, tofile='b/'+file))
        if dest:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / (name+'.patch')).write_text(patch)
        print('ANCHOR %s file=%s function=%s matches=%s' % (name, file, function, result.stdout.strip()))

    def unique(body, anchor, want=1):
        result = subprocess.run(['/usr/bin/grep','-F','-c','--',anchor],input=body,text=True,capture_output=True)
        assert result.returncode==0 and int(result.stdout)==want, (anchor,result.stdout)
        return result.stdout.strip()
    for name, files in {'M8':['node/bpf/xdrop_main.c'],'N3':['node/bpf/xdrop_main.c','node/bpf/xdrop_gate.c'],'N6':['node/agent/main.go']}.items():
        patches = []
        for file in files:
            text = (source/file).read_text()
            if name=='N3':
                function,anchor = 'BPF_MAP_DEF(devmap)','BPF_MAP_DEF(devmap)'
                unique(text,anchor); start = text.index(anchor); end = text.index('};',start)+2
                body = text[start:end]; unique(body,'BPF_MAP_TYPE_DEVMAP_HASH')
                changed = text[:start]+body.replace('BPF_MAP_TYPE_DEVMAP_HASH','BPF_MAP_TYPE_DEVMAP')+text[end:]
            elif name=='M8':
                function,anchor = 'xdp_firewall_main','// === CIDR two-stage lookup (after exact blacklist miss) ==='
                start = text.index('int xdp_firewall_main('); body = text[start:text.index('\n}',start)+2]
                unique(body,anchor); start = text.index(anchor); end = text.index('// Both exact and CIDR lookups',start)
                block = text[start:end]; needle = 'return bpf_redirect_map(&devmap, ingress_ifindex, 0);'
                unique(block,needle,3)
                changed = text[:start]+block.replace(needle,'return XDP_PASS;')+text[end:]
                print('ANCHOR M8 CIDR replacements=3')
            else:
                function,anchor = 'main','// FF state must be ready before any new program can receive traffic.'
                start = text.index('func main('); body = text[start:text.index('\n}',start)+2]
                unique(body,anchor)
                start = text.index('\t'+anchor); end = text.index('\t// Phase 8: XDP entry point',start)
                block = text[start:end]; changed = text[:start]+text[end:]
                target = '\t// Initialize API handlers before XDP attach'
                unique(body,target)
                changed = changed.replace(target,block+target,1)
            patches.append(''.join(difflib.unified_diff(text.splitlines(True),changed.splitlines(True),fromfile='a/'+file,tofile='b/'+file)))
            print('ANCHOR %s file=%s function=%s matches=1' % (name,file,function))
        if dest: (dest/(name+'.patch')).write_text(''.join(patches))


def frames(source):
    text = (source / 'controller/core/api/ff_lab_test.go').read_text()
    block = text.split('// FF_FRAME_BEGIN:', 1)[1].split('\n', 1)[1].split('// FF_FRAME_END', 1)[0]
    capture = text.split('// FF_CAPTURE_BEGIN:', 1)[1].split('\n', 1)[1].split('// FF_CAPTURE_END', 1)[0]
    cells_line = re.search(r'^var ffCells = strings.Fields\("([^"]+)"\)', text, re.M)
    assert cells_line, 'shared sender cells missing'
    gap = text.split('func (f *ffLab) gap() {', 1)[1].split('\nfunc ', 1)[0]
    gap_phase, gap_dir, gap_cell = re.search(r'"\|([^|]+)\|([^|]+)\|([^|]+)\|"', gap).groups()
    phases = set(re.findall(r'f\.phase\("([^"]+)"\)', text)) | {gap_phase}
    phase = text.split('func (f *ffLab) phase(phase string) {', 1)[1].split('\nfunc ', 1)[0]
    dirs = set(re.findall(r'"([^"]+)"', re.search(r'for _, dir := range \[\]string\{([^}]+)\}', phase).group(1))) | {gap_dir}
    for name, actual in [('Phases', phases), ('Dirs', dirs)]:
        declared = set(re.search(r'var ffCapture'+name+r' = strings.Fields\("([^"]+)"\)', capture).group(1).split())
        assert actual == declared, ('capture/send vocabulary differs', name, actual, declared)
        print('MARK_VOCAB set=%s equal=1 values=%s' % (name, ','.join(sorted(actual))), flush=True)
    spec = block.split('func ffSpec(cell string) ffFrameSpec {', 1)[1].split('\nfunc ', 1)[0]
    assert set(cells_line.group(1).split()) == set(re.findall(r'"(F-[^"]+)"', spec)) | {gap_cell}
    assert 'has(ffCells, parts[4])' in capture, 'capture must use shared ffCells'
    print('MARK_VOCAB set=Cells shared=ffCells spec_equal=1 values='+','.join(cells_line.group(1).split()), flush=True)
    program = '''package main
import ("bytes"; "encoding/binary"; "fmt"; "net"; "strings"; "sync"; "time")
''' + block + '\n' + cells_line.group(0) + '\n' + capture + '''
func captureSelf() {
 mark, spec := "FF1|inb|P1|wan_to_lan|F-miss4|", ffSpec("F-miss4")
 sent := &ffSentFrames{}
 for seq := uint32(0); seq < 20; seq++ {
  frame := ffFrame(spec, mark, seq)
  if sent.send(seq, frame, func() error { return nil }) != nil { panic("send fixture") }
  frame[0] ^= 1 // Mutating the caller's buffer must not alter the saved bytes.
 }
 valid := func(r ffCapture) bool { return r.errors == 0 && r.duplicates == 0 && r.invalid == 0 && len(r.got) == r.equal }
 control := ffCapture{got: map[uint32]bool{}}
 shifted := ffCapture{got: map[uint32]bool{}}
 for seq := uint32(0); seq < 20; seq++ {
  control.accept(append(ffFrame(spec, mark, seq), 0, 0), mark, sent)
  shifted.accept(ffFrame(spec, mark, seq+1000), mark, sent)
 }
 if !valid(control) || len(control.got) != 20 { panic("capture control") }
 pass := valid(shifted) && len(shifted.got) == 20
 if pass || shifted.invalid != 20 || len(shifted.got) != 0 { panic("shifted sequence accepted") }
 fmt.Printf("CAPTURE_SELF actual_go=1 seq_offset=1000 sent=20 received=%d invalid_frames=%d fixture_valid=%t pass=%t\\n", len(shifted.got), shifted.invalid, valid(shifted), pass)
 bad := ffCapture{got: map[uint32]bool{}}
 truncated := ffFrame(spec, mark, 0)
 bad.accept(truncated[:len(truncated)-1], mark, sent)
 changed := ffFrame(spec, mark, 0); changed[0] ^= 1
 bad.accept(changed, mark, sent)
 failed := ffFrame(spec, mark, 20)
 if sent.send(20, failed, func() error { return fmt.Errorf("synthetic send failure") }) == nil { panic("failed-send fixture") }
 bad.accept(failed, mark, sent)
 if valid(bad) || bad.invalid != 3 || len(bad.got) != 1 { panic("invalid frame accepted") }
 fmt.Println("CAPTURE_SELF actual_go=1 zero_padding=ACCEPT immutable_original=PASS truncated=REJECT changed_bytes=REJECT failed_send_sequence=REJECT")
}
func markSelf() {
 fresh := func() ffCapture { return ffCapture{got: map[uint32]bool{}} }
 valid := func(r ffCapture) bool { return r.errors == 0 && r.duplicates == 0 && r.invalid == 0 && len(r.got) == r.equal }
 makeSent := func(mark, cell string) *ffSentFrames {
  sent := &ffSentFrames{}
  for seq := uint32(0); seq < 20; seq++ {
   if sent.send(seq, ffFrame(ffSpec(cell), mark, seq), func() error { return nil }) != nil { panic("mark send fixture") }
  }
  return sent
 }
 corrupt := func(frame []byte, mark string) []byte {
  pos := bytes.Index(frame, []byte(mark)); if pos < 0 { panic("mark fixture") }
  frame[pos+len(mark)-2] ^= 1 // One byte of the current cell name, not another legal name.
  return frame
 }
 dropMark := "FF1|inb|P1|wan_to_lan|F-ex|"
 dropSent, drop := makeSent(dropMark, "F-ex"), fresh()
 for seq := uint32(0); seq < 20; seq++ { drop.accept(corrupt(ffFrame(ffSpec("F-ex"), dropMark, seq), dropMark), dropMark, dropSent) }
 pass := valid(drop) && len(drop.got) == 0
 if pass || drop.invalid != 20 || len(drop.got) != 0 { panic("drop mark corruption accepted") }
 fmt.Printf("MARK_SELF case=drop_mark_corruption delivered=20 received=%d byte_equal=%d invalid_frames=%d fixture_valid=%t pass=%t\\n",len(drop.got),drop.equal,drop.invalid,valid(drop),pass)
 mark := "FF1|inb|P2|wan_to_lan|F-miss4|"
 sent, normal, duplicate := makeSent(mark,"F-miss4"), fresh(), fresh()
 for seq := uint32(0); seq < 20; seq++ {
  original := ffFrame(ffSpec("F-miss4"),mark,seq)
  normal.accept(original,mark,sent); duplicate.accept(original,mark,sent)
  duplicate.accept(corrupt(ffFrame(ffSpec("F-miss4"),mark,seq),mark),mark,sent)
 }
 if !valid(normal) || len(normal.got) != 20 || normal.equal != 20 || normal.invalid != 0 { panic("normal capture") }
 fmt.Printf("MARK_SELF case=normal_20 received=%d byte_equal=%d invalid_frames=%d pass=true\\n",len(normal.got),normal.equal,normal.invalid)
 if valid(duplicate) || duplicate.invalid != 20 || len(duplicate.got) != 20 || duplicate.equal != 20 { panic("corrupt duplicate accepted") }
 fmt.Printf("MARK_SELF case=corrupt_duplicate delivered=40 received=%d byte_equal=%d invalid_frames=%d fixture_valid=%t pass=false\\n",len(duplicate.got),duplicate.equal,duplicate.invalid,valid(duplicate))
 gapMark := "FF1|inb|S|wan_to_lan|F-miss4|"
 gapSent, gap := makeSent(gapMark,"F-miss4"), fresh()
 for seq := uint32(0); seq < 20; seq++ { gap.accept(corrupt(ffFrame(ffSpec("F-miss4"),gapMark,seq),gapMark),gapMark,gapSent) }
 if valid(gap) || gap.invalid != 20 || len(gap.got) != 0 { panic("gap mark corruption accepted") }
 fmt.Printf("MARK_SELF case=gap_mark_corruption actual_received=20 recorded_received=%d invalid_frames=%d capture_valid=%t\\n",len(gap.got),gap.invalid,valid(gap))
 backlog := fresh()
 for _, phase := range ffCapturePhases { for _, dir := range ffCaptureDirs { for _, cell := range ffCells {
  other := "FF1|inb|"+phase+"|"+dir+"|"+cell+"|"
  if other != mark {
   frame := ffFrame(ffSpec(cell),other,0)
   backlog.accept(frame,mark,sent); backlog.accept(append(frame,0,0),mark,sent)
  }
 } } }
 if !valid(backlog) || len(backlog.got) != 0 || backlog.invalid != 0 { panic("legal backlog rejected") }
 fmt.Printf("MARK_SELF case=legal_other_cell received=%d invalid_frames=%d ignored=true\\n",len(backlog.got),backlog.invalid)
 topology := fresh()
 for port := byte(1); port <= 4; port++ {
  frame := ffFrame(ffSpec("F-miss4"),"TOPOLOGY-NOISE",0); copy(frame[6:12],[]byte{2,0,0,0,0x0f,port})
  topology.accept(frame,mark,sent)
 }
 if !valid(topology) || len(topology.got) != 0 || topology.invalid != 0 { panic("topology frame not ignored") }
 fmt.Printf("MARK_SELF case=topology_source_mac received=%d invalid_frames=%d ignored=true\\n",len(topology.got),topology.invalid)
 for _, name := range []string{"source_mac_bit_flip","source_mac_topology","source_mac_corrupt_duplicate","gap_source_mac_bit_flip"} {
  current, cell := dropMark, "F-ex"
  if name == "source_mac_corrupt_duplicate" { current, cell = mark, "F-miss4" }
  if name == "gap_source_mac_bit_flip" { current, cell = gapMark, "F-miss4" }
  originals, bad := makeSent(current,cell), fresh()
  for seq := uint32(0); seq < 20; seq++ {
   frame := ffFrame(ffSpec(cell),current,seq)
   if name == "source_mac_corrupt_duplicate" { bad.accept(frame,current,originals) }
   if name == "source_mac_topology" { copy(frame[6:12],[]byte{2,0,0,0,0x0f,1}) } else { frame[11] ^= 1 }
   bad.accept(frame,current,originals)
  }
  if valid(bad) || bad.invalid != 20 || len(bad.got) != 20 { panic("source MAC corruption accepted: "+name) }
  if name == "source_mac_corrupt_duplicate" {
   if bad.equal != 20 || bad.duplicates != 20 { panic("source MAC duplicate fixture") }
  } else if bad.equal != 0 { panic("source MAC comparison bypassed") }
  fmt.Printf("MARK_SELF case=%s received=%d byte_equal=%d invalid_frames=%d fixture_valid=%t capture_valid=%t pass=false\\n",name,len(bad.got),bad.equal,bad.invalid,valid(bad),valid(bad))
 }
 other := "FF1|inb|P1|wan_to_lan|F-miss4|"
 for _, name := range []string{"corrupt_current_plus_appended_other","corrupt_current_plus_other_without_seq"} {
  bad := fresh()
  for seq := uint32(0); seq < 20; seq++ {
   frame := corrupt(ffFrame(ffSpec("F-ex"),dropMark,seq),dropMark)
   frame = append(frame,[]byte(other)...)
   if name == "corrupt_current_plus_appended_other" {
    var encoded [4]byte; binary.BigEndian.PutUint32(encoded[:],seq); frame = append(frame,encoded[:]...)
   }
   bad.accept(frame,dropMark,dropSent)
  }
  if valid(bad) || bad.invalid != 20 || len(bad.got) != 0 { panic("appended other marker accepted: "+name) }
  fmt.Printf("MARK_SELF case=%s received=%d invalid_frames=%d fixture_valid=%t pass=false\\n",name,len(bad.got),bad.invalid,valid(bad))
 }
 nonzero := fresh(); nonzero.accept(append(ffFrame(ffSpec("F-miss4"),other,0),1),mark,sent)
 if valid(nonzero) || nonzero.invalid != 1 || len(nonzero.got) != 0 { panic("nonzero backlog tail accepted") }
 fmt.Printf("MARK_SELF case=other_cell_nonzero_tail received=%d invalid_frames=%d fixture_valid=%t pass=false\\n",len(nonzero.got),nonzero.invalid,valid(nonzero))
 for _, item := range [][2]string{
  {"scenario_corruption","FF1|inx|P2|wan_to_lan|F-miss4|"},
  {"unknown_phase","FF1|inb|P9|wan_to_lan|F-miss4|"},
  {"unknown_dir","FF1|inb|P2|unknown|F-miss4|"},
  {"unknown_cell","FF1|inb|P2|wan_to_lan|F-unknown|"},
  {"prefix_corruption","XF1|inb|P2|wan_to_lan|F-miss4|"},
 } {
  bad := fresh(); bad.accept(ffFrame(ffSpec("F-miss4"),item[1],0),mark,sent)
  if valid(bad) || bad.invalid != 1 || len(bad.got) != 0 { panic("bad marker ignored: "+item[0]) }
  fmt.Printf("MARK_SELF case=%s received=%d invalid_frames=%d fixture_valid=%t\\n",item[0],len(bad.got),bad.invalid,valid(bad))
 }
}
func main() {
 cells := ffCells
 for _, cell := range cells {
  want := ffSpec(cell); frame := ffFrame(want, "FF-SELF|", 7)
  got, payload, err := ffParse(frame)
  want.Src, want.Dst = net.ParseIP(want.Src).String(), net.ParseIP(want.Dst).String()
  if err != nil || got != want || !bytes.Equal(payload, append([]byte("FF-SELF|"),0,0,0,7)) { panic("frame roundtrip: "+cell) }
  fmt.Printf("FRAME_SELF cell=%s bytes=%d roundtrip=1\\n", cell, len(frame))
 }
 captureSelf()
 markSelf()
}
'''
    with tempfile.TemporaryDirectory(prefix='ff-frame-', dir=os.environ['TMPDIR']) as temp:
        file = Path(temp) / 'main.go'
        file.write_text(program)
        subprocess.run(['go', 'run', str(file)], check=True,
                       env=dict(os.environ, GOWORK='off', GO111MODULE='off', GOPROXY='off', GOTOOLCHAIN='local'))


def pairs(source):
    text = (source/'controller/core/api/ff_lab_test.go').read_text()
    block = text.split('// FF_PAIR_BEGIN:',1)[1].split('\n',1)[1].split('// FF_PAIR_END',1)[0]
    program = 'package main\nimport ("crypto/sha256";"encoding/json";"fmt";"os";"path/filepath")\n'+block+'''
func main() {
 root,err:=os.MkdirTemp("","ns-pairs-"); if err!=nil {panic(err)};defer os.RemoveAll(root)
 manifest:=filepath.Join(root,"generations.json")
 entries:=map[string]map[string]string{}
 add:=func(name,source string)string{p:=filepath.Join(root,name);b:=[]byte("fixture "+name);if os.WriteFile(p,b,0600)!=nil{panic(name)};entries[p]=map[string]string{"source":source,"sha":fmt.Sprintf("%x",sha256.Sum256(b))};return p}
 old:="b9e06b79fe384aba783c692ec88bad3164c81683";pre:="d39805f4910e4245004cf1157056c0ad749ef379"
 oa,oc:=add("old-agent",old),add("old-controller",old)
 pa,pc:=add("pre-agent",pre),add("pre-controller",pre)
 nc:=add("new-controller",old+"+ns")
 b,_:=json.Marshal(entries);if os.WriteFile(manifest,b,0600)!=nil {panic("manifest")}
 for _,x:=range []struct{name,a,c,want string; good bool}{{"control-upg",oa,oc,old,true},{"control-ctl",pa,pc,pre,true},{"V15",oa,nc,old,false},{"V16",oa,pc,pre,false}} {
  got:=ffPair(x.a,x.c,manifest,x.want);if got!=x.good {panic(x.name)}
  fmt.Printf("PAIR_SELF name=%s actual_selected_sha_checked=true accepted=%t expected=%t\\n",x.name,got,x.good)
 }
 if os.WriteFile(pa,[]byte("changed fixture"),0600)!=nil || ffPair(pa,pc,manifest,pre){panic("actual file SHA not checked")}
}
'''
    with tempfile.TemporaryDirectory(prefix='ff-pair-self-') as temp:
        file = Path(temp)/'main.go'; file.write_text(program)
        subprocess.run(['go','run',str(file)],check=True,env=dict(os.environ,GOWORK='off',GO111MODULE='off',GOPROXY='off',GOTOOLCHAIN='local'))


def oracles():
    """Synthetic records test rejection paths; these are never lab evidence."""
    import runner as r
    def stream(scene):
        v = dict(scenario=scene,sent_unique=5001,received_unique=5001,lost=0,send_failures=0,max_send_gap_ms=1,window_sent=1001,window_ms=1000,
            t_first_send_utc='2026-10-13T00:00:00Z',t_last_send_utc='2026-10-13T00:00:05Z',sigterm_utc='2026-10-13T00:00:01Z',ready_utc='2026-10-13T00:00:02Z',
            tx_started_utc='2026-10-13T00:00:00Z',rx_started_utc='2026-10-13T00:00:00Z',rx_ended_utc='2026-10-13T00:00:06Z',
            first_received_send_utc='2026-10-13T00:00:00Z',last_received_send_utc='2026-10-13T00:00:05Z',pre_received=True,post_received=True,
            lost_outside_window=0,loss_localized=True,tp_drops=0,stats_ok=True,max_receive_gap_ms=1,receive_errors=0,invalid_frames=0,duplicates=0,byte_equal=5001,validity=[True]*5,base_valid=True,**{'pass':True})
        if scene=='ctl': v.update(received_unique=4991,byte_equal=4991,lost=10)
        return v
    def fixture(m):
        scenes = r.M_SCENES[m] if m else r.SCENES
        active = [] if m=='N3' else scenes
        records = []
        for k,(n,e) in r.expected(active).items():
            records.append(('FFCELL',dict(zip(['scenario','phase','dir','cell'],k),sent=n,received=e[0],byte_equal=e[0],expect=e,fixture_valid=True,invalid_frames=0,
                t_first_send_utc='2026-10-13T00:00:00Z',t_last_recv_utc='2026-10-13T00:00:30Z' if e[0] else '',t_complete_utc='2026-10-13T00:00:20Z',**{'pass':True})))
        for scene,p,i in sorted(r.count_keys(active)):
            factor = 2 if scene=='both' else 1; want = (50 if i in ['R-rl.match_count','R-crl.match_count'] else 20)*factor
            if i=='whitelisted_packets': want = 20*factor if p=='P1' else 0
            if i=='rate_limited_packets': want = 98*factor
            records.append(('FFCOUNT',dict(scenario=scene,phase=p,item=i,before=0,after=want,delta=want,expect=want,measurement_valid=True,**{'pass':True})))
        links = [dict(name=n,promisc=True,xdp=True) for n in ['w0','l0']]
        for scene in active:
            records += [('FFEND',dict(scenario=scene,complete=True)),('FFSHAPE',dict(scenario=scene,api_ready=True,healthy=scene!='hidx',xdp_info=dict(mode='fast_forward',interfaces=[dict(name=n,role=role,attach_mode='generic') for n,role in [('w0','inbound'),('l0','outbound')]]),links=copy.deepcopy(links),**{'pass':True})),('FFPOST',dict(scenario=scene,agent_exited=True,links=copy.deepcopy(links))),('FFPOSTTERM',dict(scenario=scene,agent_exited=True,checked=scene in ['inb','both','hidx'],promisc=True,xdp=True,links=copy.deepcopy(links))),('FFSTREAM',stream(scene))]
            if scene in ['inb','both']: records += [('FFSELECTOR',dict(scenario=scene,phase=p,before=0,after=1)) for p in ['P2','P3']]
        for scene in scenes:
            records += [('FFPAIR',dict(scenario=scene,phase=phase,source=r.BASELINE['ctl'] if scene=='ctl' else r.BASELINE['upg'] if scene=='upg' and phase=='P0' else '4cdb3f91967a96ffe974596b3c80719db1c71172+ns',selected_sha_match=True)) for phase in (['P0'] if m=='N3' else ['P0','S'])]
            records += [('FFALIVE',dict(scenario=scene,event='start',alive=True,same_mount=True,t_utc='2026-10-13T00:00:20Z',pid=100+i)) for i in range(1 if m=='N3' else 2)]
            records += [('FFMOUNT',dict(scenario=scene,dev_different=True,fstype_bpf=True,**{'pass':True})),('FFSECRET',dict(scenario=scene,matches=0,files_checked=1,node_positive_control=True,secret_classes=1 if scene=='hidx' else 5,**{'pass':True})),('FFEXIT',dict(scenario=scene,timeout=False,test_terminal='PASS'))]
        if 'hidx' in scenes: records.append(('FFHIDX',dict(scenario='hidx',witness='HIDX_FORWARD',**{'pass':True})))
        if m in r.M_TESTS:
            records += [('GOTEST',dict(Action=action,Test=r.M_TESTS[m],Package='github.com/littlewolf9527/xdrop/node/agent')) for action in ['run','pass']]
        return scenes,records
    def check(m,records,scenes,evidence=False):
        with tempfile.TemporaryDirectory(prefix='ff-oracle-',dir=os.environ['TMPDIR']) as temp:
            out = Path(temp)
            (out/'supervisor-synthetic.log').write_text(''.join(k+' '+json.dumps(v)+'\n' for k,v in records if k!='GOTEST'))
            (out/'mutation-tests.jsonl').write_text(''.join(json.dumps(v)+'\n' for k,v in records if k=='GOTEST'))
            a = SimpleNamespace(baseline=r.BASELINE["upg"],source_head="4cdb3f91967a96ffe974596b3c80719db1c71172",out=out,mutation=m,only=scenes)
            output = io.StringIO()
            with contextlib.redirect_stdout(output): result = r.collect(a,scenes,{'run_leftover':[]},{'run_leftover':[]},True)
            return (result,json.loads((out/'results.json').read_text()),output.getvalue()) if evidence else result
    def redden(m,records):
        for kind,v in records:
            k = tuple(v.get(n) for n in ['scenario','phase','dir','cell'])
            if kind=='FFCELL' and k in r.must_red(m): v.update(received=1 if v['expect']==[0,0] else 0,byte_equal=1 if v['expect']==[0,0] else 0,**{'pass':False})
            if kind=='FFPOSTTERM' and m=='N2':
                v['promisc']=False
                for link in v['links']: link['promisc']=False
            if kind=='FFHIDX' and m=='N3': v.update(witness='HIDX_START_FAIL',exit=1,within_30s=True,loaded=True,devmap_e2big=True,health_seen=False)
            if kind=='GOTEST' and v['Action']=='pass': v['Action']='fail'
            if kind=='FFEXIT' and m!='N6': v['test_terminal']='FAIL'
        # M8's counter expectation changes with the mutated received count.
        if m=='M8':
            for kind,v in records:
                if kind=='FFCOUNT' and v['phase']=='P1' and v['item']=='rate_limited_packets': v.update(expect=99,**{'pass':False})
    scenes,base = fixture(None)
    assert len(r.expected(['inb','both']))==200 and len(r.count_keys(scenes))==76 and check(None,base,scenes)
    assert not check(None,base[1:],scenes), 'missing cell accepted'
    assert not check(None,base+[base[0]],scenes), 'duplicate cell accepted'
    zero=copy.deepcopy(base); zero[0][1]['sent']=0
    assert not check(None,zero,scenes), 'zero sending accepted'
    print('ORACLE_SELF synthetic=1 baseline=218 ctl_extra=12 counts=76 missing=REJECT duplicate=REJECT zero_sent=REJECT')
    for m in r.M_SCENES:
        scenes,records=fixture(m)
        assert not check(m,records,scenes), 'missing must-red accepted: '+m
        redden(m,records)
        assert check(m,records,scenes), 'must-red rejected: '+m
        polluted=copy.deepcopy(records)
        outside=next((v for kind,v in polluted if kind=='FFCELL' and not r.allowed(m,tuple(v[n] for n in ['scenario','phase','dir','cell']),positive=v['expect'][1]>0)),None)
        if outside is not None:
            outside.update(received=1 if outside['expect']==[0,0] else 0,byte_equal=1 if outside['expect']==[0,0] else 0,**{'pass':False})
            assert not check(m,polluted,scenes), 'outside failure accepted'
        invalid=copy.deepcopy(records)
        for kind,v in invalid:
            if kind=='FFCELL': v['fixture_valid']=False
            if kind=='FFHIDX' and m=='N3': v['loaded']=False
            if kind=='GOTEST': v['Action']='build-fail'
        assert not check(m,invalid,scenes), 'fixture/build failure accepted: '+m
        print('ORACLE_SELF synthetic=1 mutation=%s must_red=ACCEPT missing_must=REJECT fixture_invalid=REJECT outside=%s' % (m,'REJECT' if outside is not None else 'NAMED_WITNESS_ONLY'))
    for m in ['M5','M7',None]:
        scenes,records=fixture(m)
        if m: redden(m,records)
        v=next(v for kind,v in records if kind==('FFCOUNT' if m=='M7' else 'FFCELL'))
        if m=='M7': v['expect']+=1
        else: v['pass']=not v['pass']
        result,report,output=check(m,records,scenes,True)
        assert not result and report['invalid'] and not report['gates']['G1'] and not report['gates']['G2'] and 'verdict=RED_OK' not in output
        print('EVIDENCE_SELF synthetic=1 mutation=%s contradictory_pass_expect=REJECT RED_OK=REJECT' % (m or 'baseline'))
    for case in ['mid_send_pause','receiver_early_stop','nothing_received','mid_receiver_stall_drops']:
        scenes,records=fixture(None); v=next(v for kind,v in records if kind=='FFSTREAM' and v['scenario']=='ctl')
        if case=='mid_send_pause': v.update(max_send_gap_ms=100,window_sent=2)
        if case=='receiver_early_stop': v['rx_ended_utc']='2026-10-13T00:00:04Z'
        if case=='nothing_received': v.update(received_unique=0,byte_equal=0,lost=5001,first_received_send_utc='',last_received_send_utc='',pre_received=False,post_received=False)
        if case=='mid_receiver_stall_drops': v.update(tp_drops=10,max_receive_gap_ms=300)
        # Raw measurements must reject even if the producer still claims valid/pass.
        assert r.stream_failures(v)[0] and not check(None,records,scenes)
        print('STREAM_SELF synthetic=1 case=%s verdict=RED' % case)
    # Mutation exceptions never waive transport validity or receiver coverage.
    for m in r.M_SCENES:
        for item in ['base','continuous','window','coverage','pre','post','receive','loss']:
            expected = (item in ['loss','continuous'] and m in ['M3','M5','M7','N6']) or (item=='pre' and m in ['M3','M5','M7']) or (item=='post' and m in ['M3','M7'])
            assert r.stream_allowed(m,item)==expected, (m,item)
        print('STREAM_ALLOW_SELF synthetic=1 mutation=%s exact_PLAN_A1_exceptions=PASS' % m)
    # 所有者 10-15 改 A1：只破 ①（发送间隔 25 ms，其余有效）——包都到了 ⇒ 全部场景判过（G3 / G4 PASS），间隔只记录。
    for scene in ['inb','both','hidx','upg','ctl']:
        scenes,records=fixture(None); v=next(v for kind,v in records if kind=='FFSTREAM' and v['scenario']==scene)
        v['max_send_gap_ms']=25; v['validity'][0]=False
        bad,consistent=r.stream_failures(v)
        assert bad==set() and consistent, (scene,bad,consistent)
        result,report,_=check(None,records,scenes,True)
        assert result and not report['invalid'] and (report['gates']['G4'] if scene=='ctl' else report['gates']['G3']), 'continuous-only gap must pass: '+scene
        print('STREAM_A1_SELF synthetic=1 case=continuous_only scene=%s verdict=PASS' % scene)
    # 盲审 r1 P1 / r2 P2：内部 --supervisor 入口在任何挂载前拒绝缺前提的调用（含其余合法、仅 mount namespace 与 PID 1 相同）
    with tempfile.TemporaryDirectory(prefix='ff-sup-',dir=os.environ['TMPDIR']) as temp:
        root = Path(temp).resolve(); inside = root/'scratch'; inside.mkdir()
        cases = {'scene_missing':dict(scene=None,host_dev=7,scratch=inside),'host_dev_missing':dict(scene='inb',host_dev=0,scratch=inside),
                 'scratch_outside_root':dict(scene='inb',host_dev=7,scratch=Path(temp).resolve().parent),
                 'same_mount_ns':dict(scene='inb',host_dev=7,scratch=inside)}
        real_run, real_ns = r.run, r.mount_ns_private
        for case,kw in cases.items():
            calls = []
            r.run = lambda cmd,*x,**y: calls.append(list(map(str,cmd))) or b''
            r.mount_ns_private = lambda: case != 'same_mount_ns'
            try:
                r.supervisor(SimpleNamespace(baseline=r.BASELINE["upg"],work_root=root,mutation=None,**kw)); raised = False
            except AssertionError: raised = True
            finally: r.run, r.mount_ns_private = real_run, real_ns
            assert raised and not calls, (case, calls)
            print('SUPERVISOR_GUARD_SELF synthetic=1 case=%s mounts_before_reject=0 verdict=REJECT' % case)
        # 盲审 r2 P2：bpffs 挂载失败 ⇒ ⛔ umount（只卸自己挂上的），原始错误原样抛出
        calls = []
        def failing(cmd,*x,**y):
            calls.append(list(map(str,cmd)))
            if cmd[:3] == ['mount','-t','bpf']: raise RuntimeError('synthetic bpffs mount failure')
            return b''
        r.run, r.mount_ns_private = failing, (lambda: True)
        try:
            r.supervisor(SimpleNamespace(baseline=r.BASELINE["upg"],work_root=root,mutation=None,scene='inb',host_dev=7,scratch=inside)); err = None
        except RuntimeError as e: err = str(e)
        finally: r.run, r.mount_ns_private = real_run, real_ns
        assert err == 'synthetic bpffs mount failure' and not any(c[0] == 'umount' for c in calls), (err, calls)
        print('SUPERVISOR_MOUNT_FAIL_SELF synthetic=1 umount_calls=0 original_error=kept verdict=PASS')
    # 盲审 r2 P1：父进程把 --work-root 传给 supervisor 子进程
    src = Path(r.__file__).read_text()
    assert src.count("'--supervisor'") == 2 and "'--work-root',a.work_root,'--host-dev'" in src, 'supervisor argv must forward --work-root'
    print('SUPERVISOR_ARGV_SELF synthetic=1 forwards_work_root=1 verdict=PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--patch-out', type=Path)
    parser.add_argument('--frames', action='store_true')
    parser.add_argument('--oracles', action='store_true')
    args = parser.parse_args()
    anchors(args.source, args.patch_out)
    if args.frames:
        frames(args.source)
        pairs(args.source)
    if args.oracles:
        oracles()
