//go:build linux && integration

package api

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
	"golang.org/x/sys/unix"
)

type flipProbe struct {
	Name  string
	P     eval.B1Packet
	Frame []byte
}

func flipTrafficProbes(t *testing.T) []flipProbe {
	t.Helper()
	var out []flipProbe
	for _, row := range []struct {
		name, src, dst string
		ttl            byte
	}{{"D-a", "10.200.1.1", "10.201.1.1", 64}, {"D-c", "10.210.0.1", "10.211.0.1", 64}, {"Q", "10.202.0.1", "10.201.1.1", 64}, {"exact", "10.203.0.1", "10.201.1.1", 64}, {"condition64", "10.204.0.1", "10.201.1.1", 64}, {"condition63", "10.204.0.1", "10.201.1.1", 63}, {"miss", "10.220.0.1", "10.221.0.1", 64}} {
		p := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr(row.src), Dst: netip.MustParseAddr(row.dst), Sport: 12345, Dport: 80, Proto: 6}, Length: 40, Flags: 2}, TTL: row.ttl}
		frame := b7Packet()
		src, dst := p.Src.As4(), p.Dst.As4()
		copy(frame[26:], src[:])
		copy(frame[30:], dst[:])
		frame[22], frame[46] = p.TTL, 0x50
		got, e := cut53IPv4Attributes(frame)
		if e != nil || got != p {
			t.Fatalf("FLIPTRAFFIC_FRAME %s got=%+v want=%+v err=%v", row.name, got, p, e)
		}
		out = append(out, flipProbe{row.name, p, frame})
	}
	return out
}
func flipTrafficState(state, iteration int) []Rule {
	r := func(id uint32) Rule {
		return Rule{ID: fmt.Sprint("traffic-", id), LogicalID: id, Protocol: "all", Action: "drop"}
	}
	var rows []Rule
	if state == 1 || state == 2 {
		a := r(11001)
		a.SrcCIDR = "10.200.0.0/20"
		if state == 2 {
			a = r(11002)
			a.SrcCIDR = "10.200.1.0/24"
		}
		rows = append(rows, a)
		if state == 1 {
			q := r(uint32(20000 + iteration))
			q.SrcCIDR = "10.202.0.0/24"
			rows = append(rows, q)
		}
	} else {
		a := r(11003)
		a.SrcCIDR = "10.210.0.0/24"
		if state == 4 {
			a = r(11004)
			a.DstCIDR = "10.211.0.0/24"
		}
		rows = append(rows, a)
	}
	if state == 1 || state == 3 {
		a := r(11005)
		a.SrcIP = "10.203.0.1"
		rows = append(rows, a)
	}
	a := r(11006)
	a.SrcIP = "10.204.0.1"
	a.TTL = new(string)
	*a.TTL = "64"
	if state == 2 || state == 4 {
		*a.TTL = "63"
	}
	return append(rows, a)
}
func flipDelta(t *testing.T, h *Handlers, old, next []Rule) []CommitGroup {
	t.Helper()
	groups := map[string]CommitGroup{}
	for _, r := range old {
		g := cut55Group(t, h, r)
		groups[string(g.Key)] = g
	}
	for _, r := range next {
		g := cut55Group(t, h, r, r)
		groups[string(g.Key)] = g
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]CommitGroup, 0, len(keys))
	for _, k := range keys {
		out = append(out, groups[k])
	}
	return out
}
func flipTrafficOracle(t *testing.T, tables eval.Tables, rules []Rule, p eval.B1Packet) uint32 {
	t.Helper()
	rs := eval.B1RuleSet{}
	for i, r := range rules {
		v := eval.B1Rule{Rule: eval.Rule{ID: r.ID}, LogicalID: r.LogicalID, HasConditions: r.TTL != nil, TTL: r.TTL}
		mask := eval.Mask(0)
		if r.SrcCIDR != "" || r.DstCIDR != "" {
			if r.SrcCIDR != "" {
				v.CIDRKey.SrcID = uint32(i + 1)
				rs.SrcPrefixes = append(rs.SrcPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.SrcCIDR), ID: uint32(i + 1)})
				mask |= eval.SrcIP
			}
			if r.DstCIDR != "" {
				v.CIDRKey.DstID = uint32(i + 1)
				rs.DstPrefixes = append(rs.DstPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.DstCIDR), ID: uint32(i + 1)})
				mask |= eval.DstIP
			}
			rs.CIDR = append(rs.CIDR, v)
			for _, combo := range tables.Order {
				if tables.Masks[combo] == mask {
					rs.CIDRBitmap |= 1 << combo
				}
			}
		} else {
			v.Key.Src = netip.MustParseAddr(r.SrcIP)
			mask = eval.SrcIP
			rs.Exact = append(rs.Exact, v)
			for _, combo := range tables.Order {
				if tables.Masks[combo] == mask {
					rs.ExactBitmap |= 1 << combo
				}
			}
		}
	}
	d, e := eval.EvaluateB1Cut54(tables, rs, p)
	if e != nil {
		t.Fatal(e)
	}
	if d.ActionCode == ActionDrop {
		return 1
	}
	return 2
}
func flipTables(t *testing.T) eval.Tables {
	t.Helper()
	root := os.Getenv("XDROP_B1_ROOT")
	if root == "" {
		root, _ = filepath.Abs("../../..")
	}
	tables, e := eval.LoadTables(root, eval.B1)
	if e != nil {
		t.Fatal(e)
	}
	return tables
}

type flipPacketRecord struct {
	Start, End int64
	Probe      int
	Verdict    uint32
}
type flipRequestRecord struct {
	Start, End int64
	State      int
}

// PLAN verbatim: 状态 S_j 的「可能区间」= [第 j 次请求开始,
// 第 j+1 次 HTTP 回执]（S_0 自 −∞ 起，末态到 +∞）。
// Times are monotonic time.Since(origin).Nanoseconds, for requests, replies,
// packets and stage observations alike. Endpoints are inclusive.
func flipPossible(requests []flipRequestRecord, j int, p flipPacketRecord) bool {
	lo, hi := int64(-1<<63), int64(1<<63-1)
	if j > 0 {
		lo = requests[j-1].Start
	}
	if j < len(requests) {
		hi = requests[j].End
	}
	return lo <= p.End && p.Start <= hi
}
func TestFlipTrafficELF(t *testing.T) {
	defer flipQuiet()()
	h, _, program, c := flipFixture(t)
	probes := flipTrafficProbes(t)
	tables := flipTables(t)
	predictions := map[int][]uint32{}
	var installed []Rule
	steady := 0
	for state := 1; state <= 4; state++ {
		if len(installed) > 0 {
			flipCommit(t, h, flipDelta(t, h, installed, nil))
		}
		rules := flipTrafficState(state, 0)
		flipCommit(t, h, flipDelta(t, h, nil, rules))
		installed = rules
		for _, p := range probes {
			want := flipTrafficOracle(t, tables, rules, p.P)
			got, _, e := program.Test(p.Frame)
			if e != nil || got != want {
				t.Fatalf("FLIPTRAFFIC_STEADY state=S%d probe=%s bpf=%d want=%d err=%v pass=0", state, p.Name, got, want, e)
			}
			predictions[state] = append(predictions[state], want)
			steady++
		}
	}
	t.Logf("FLIPTRAFFIC_STEADY states=4 packets=%d mismatches=0 preset=commit", steady)
	var cpuset unix.CPUSet
	if e := unix.SchedGetaffinity(0, &cpuset); e != nil {
		t.Fatal(e)
	}
	var cpus []int
	for i := 0; i < 1024; i++ {
		if cpuset.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	g := min(4, len(cpus)-1)
	if g < 1 {
		t.Fatal("FLIPTRAFFIC_FIXTURE requires at least two available CPUs")
	}
	t.Logf("FLIPTRAFFIC_CPUS available=%d senders=%d", len(cpus), g)
	total, j2total, da, dc, multi, violations, j2violations := 0, 0, 0, 0, 0, 0, 0
	flips := [2]int{}
	for segment := 0; segment < 2; segment++ {
		initial := 1 + 2*segment
		flipCommit(t, h, flipDelta(t, h, installed, nil))
		installed = flipTrafficState(initial, 1)
		flipCommit(t, h, flipDelta(t, h, nil, installed))
		origin := time.Now()
		stamp := func() int64 { return time.Since(origin).Nanoseconds() }
		records := make([][]flipPacketRecord, g)
		latest := make([]atomic.Int64, g)
		counts := make([]atomic.Int64, g)
		var stop atomic.Bool
		errs := make(chan error, 2*g+2)
		var workers sync.WaitGroup
		ready := make(chan struct{}, g)
		for worker := 0; worker < g; worker++ {
			workers.Add(1)
			go func(w int) {
				defer workers.Done()
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var old unix.CPUSet
				if e := unix.SchedGetaffinity(0, &old); e != nil {
					errs <- e
					ready <- struct{}{}
					return
				}
				var one unix.CPUSet
				one.Set(cpus[w+1])
				if e := unix.SchedSetaffinity(0, &one); e != nil {
					errs <- e
					ready <- struct{}{}
					return
				}
				defer func() {
					if e := unix.SchedSetaffinity(0, &old); e != nil {
						errs <- e
					}
				}()
				ready <- struct{}{}
				for k := 0; !stop.Load(); k++ {
					idx := k % len(probes)
					start := stamp()
					got, _, e := program.Test(probes[idx].Frame)
					end := stamp()
					if e != nil {
						errs <- e
						return
					}
					records[w] = append(records[w], flipPacketRecord{start, end, idx, got})
					counts[w].Add(1)
					latest[w].Store(start)
				}
			}(worker)
		}
		for w := 0; w < g; w++ {
			<-ready
		}
		requests := []flipRequestRecord{}
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			current := installed
			for i := 0; i < 100; i++ {
				nextState := initial + 1
				if i%2 == 1 {
					nextState = initial
				}
				next := flipTrafficState(nextState, i+2)
				beforeSelector := flipSelector(t, c)
				request := flipRequestRecord{Start: stamp(), State: nextState}
				hook := func(stage string) {
					t.Logf("FLIPTRAFFIC_STAGE segment=%d request=%d stage=%s mono_ns=%d", segment, i+1, stage, stamp())
				}
				atomicStageTestHook = func(stage string, _ *Handlers) { hook(stage) }
				h.commitStageTestHook = hook
				if segment == 0 {
					result, e := h.DoAtomicSync(next)
					if e != nil || result.Failed != 0 || result.Added != len(next) {
						errs <- fmt.Errorf("atomic %+v %v", result, e)
						return
					}
				} else {
					result, e := h.DoCommitRules(flipDelta(t, h, current, next))
					if e != nil || result.Code != "committed" {
						errs <- fmt.Errorf("commit %+v %v", result, e)
						return
					}
				}
				request.End = stamp()
				if flipSelector(t, c) == beforeSelector {
					errs <- fmt.Errorf("selector did not flip")
					return
				}
				atomicStageTestHook = nil
				h.commitStageTestHook = nil
				requests = append(requests, request)
				t.Logf("FLIPTRAFFIC_REQUEST segment=%d request=%d start_ns=%d reply_ns=%d state=S%d", segment, i+1, request.Start, request.End, nextState)
				current = next
				// A completed packet whose start follows this receipt, on every sender,
				// is required before the next request can begin.
				for w := 0; w < g; w++ {
					for latest[w].Load() <= request.End {
						if len(errs) > 0 {
							return
						}
						if time.Since(origin) > 30*time.Minute {
							errs <- fmt.Errorf("post-receipt sender timeout")
							return
						}
						runtime.Gosched()
					}
				}
			}
			installed = current
		}()
		<-writerDone
		for {
			n := int64(0)
			for w := 0; w < g; w++ {
				n += counts[w].Load()
			}
			if n >= 500000 || len(errs) > 0 {
				break
			}
			runtime.Gosched()
		}
		stop.Store(true)
		workers.Wait()
		atomicStageTestHook = nil
		h.commitStageTestHook = nil
		select {
		case e := <-errs:
			t.Fatalf("FLIPTRAFFIC_FIXTURE %v", e)
		default:
		}
		if len(requests) != 100 {
			t.Fatal("FLIPTRAFFIC_EXEC missing requests")
		}
		flips[segment] = len(requests)
		qualified := make([][]int, g)
		for w := range qualified {
			qualified[w] = make([]int, len(requests))
		}
		packets, j2, bad, many, daSeg, dcSeg, cross := 0, 0, 0, 0, 0, 0, 0
		for w, stream := range records {
			for _, p := range stream {
				matches, allowed := 0, false
				only := -1
				for j := 0; j <= len(requests); j++ {
					if !flipPossible(requests, j, p) {
						continue
					}
					state := initial
					if j > 0 {
						state = requests[j-1].State
					}
					matches++
					only = j
					if p.Verdict == predictions[state][p.Probe] {
						allowed = true
					}
				}
				if matches == 1 {
					j2++
					if only > 0 {
						qualified[w][only-1]++
					}
				}
				if matches > 2 {
					cross++
				}
				if matches > 1 {
					many++
				}
				if !allowed || matches == 0 {
					if matches == 1 {
						j2violations++
					}
					bad++
					if bad < 10 {
						t.Errorf("FLIPTRAFFIC_J1 segment=%d worker=%d start=%d end=%d overlaps=%d probe=%s verdict=%d pass=0", segment, w, p.Start, p.End, matches, probes[p.Probe].Name, p.Verdict)
					}
				}
				if segment == 0 && probes[p.Probe].Name == "D-a" {
					daSeg++
				}
				if segment == 1 && probes[p.Probe].Name == "D-c" {
					dcSeg++
				}
				packets++
			}
		}
		for w := range qualified {
			for i, n := range qualified[w] {
				if n < 1 {
					t.Errorf("FLIPTRAFFIC_J2_WITNESS segment=%d worker=%d request=%d packets=%d pass=0", segment, w, i+1, n)
					bad++
				}
			}
		}
		if packets < 500000 || j2 < 100*g || segment == 0 && daSeg < 10000 || segment == 1 && dcSeg < 10000 {
			t.Errorf("FLIPTRAFFIC_EXEC segment=%d packets=%d J2=%d D_a=%d D_c=%d pass=0", segment, packets, j2, daSeg, dcSeg)
		}
		t.Logf("FLIPTRAFFIC_MULTI segment=%d cross_multiple_flips=%d overlap_at_least_two=%d", segment, cross, many)
		t.Logf("FLIPTRAFFIC_SEGMENT segment=%d flips=%d packets=%d J2=%d D_a=%d D_c=%d multi_overlap=%d violations=%d", segment, len(requests), packets, j2, daSeg, dcSeg, many, bad)
		total += packets
		j2total += j2
		da += daSeg
		dc += dcSeg
		multi += many
		violations += bad
	}
	t.Logf("FLIPTRAFFIC_VERDICT packets=%d J2=%d J2_min=%d D_a=%d D_c=%d multi_overlap=%d atomic=%d commit=%d J1_violations=%d J2_violations=%d pass=%d", total, j2total, 200*g, da, dc, multi, flips[0], flips[1], violations, j2violations, flipBool(!t.Failed()))
	if total < 1000000 || da < 10000 || dc < 10000 || j2total < 200*g {
		t.Error("FLIPTRAFFIC_EXEC aggregate quota")
	}
}

type flipWindow struct {
	counting       bool
	unarmedWrites  int
	beginNS, endNS int64
	armed, before  bool
	calls, packets int
	name, op       string
	side           int
	selector       uint64
	verdict        uint32
	err            error
	callback       func()
}
type flipTrie struct {
	cidr.TrieWriter
	name   string
	side   int
	window *flipWindow
}

func (w *flipTrie) witness(op string, before bool) {
	s := w.window
	if s.counting && before && !s.armed && s.calls == 0 {
		s.unarmedWrites++
	}
	if s.armed && s.before == before {
		s.armed = false
		s.calls++
		s.name, s.op, s.side = w.name, op, w.side
		s.callback()
	}
}
func (w *flipTrie) Put(key, value interface{}) error {
	w.witness("Put", true)
	e := w.TrieWriter.Put(key, value)
	if e == nil {
		w.witness("Put", false)
	}
	return e
}
func (w *flipTrie) Delete(key interface{}) error {
	w.witness("Delete", true)
	e := w.TrieWriter.Delete(key)
	if e == nil {
		w.witness("Delete", false)
	}
	return e
}
func TestFlipTrafficWindowsELF(t *testing.T) {
	defer flipQuiet()()
	executed := 0
	for _, kind := range []string{"a", "c"} {
		t.Run("WW-"+kind, func(t *testing.T) {
			h, _, p, c := flipFixture(t)
			s := &flipWindow{before: kind == "c"}
			var writers []cidr.TrieWriter
			for side := 0; side < 2; side++ {
				for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"} {
					if side == 1 {
						name += "_b"
					}
					writers = append(writers, &flipTrie{TrieWriter: c.Maps[name], name: name, side: side, window: s})
				}
			}
			h.cidrMgr = cidr.NewManager(writers[0], writers[1], writers[2], writers[3], writers[4], writers[5], writers[6], writers[7])
			old := Rule{ID: "WW-old", LogicalID: 30001, SrcCIDR: "10.200.0.0/20", Protocol: "all", Action: "drop"}
			next := Rule{ID: "WW-new", LogicalID: 30002, SrcCIDR: "10.200.1.0/24", Protocol: "all", Action: "drop"}
			probe := flipTrafficProbes(t)[0]
			if kind == "c" {
				old.SrcCIDR = "10.210.0.0/24"
				next.SrcCIDR = ""
				next.DstCIDR = "10.211.0.0/24"
				probe = flipTrafficProbes(t)[1]
			}
			flipCommit(t, h, []CommitGroup{cut55Group(t, h, old, old)})
			if kind == "c" {
				unrelated := Rule{ID: "WW-unrelated", LogicalID: 30003, SrcIP: "10.230.0.1", Protocol: "all", Action: "drop"}
				flipCommit(t, h, []CommitGroup{cut55Group(t, h, unrelated, unrelated)})
			}
			before := flipSelector(t, c)
			initial, _, e := p.Test(probe.Frame)
			if e != nil || initial != 1 {
				t.Fatalf("WW_PRECONDITION kind=%s bpf=%d err=%v", kind, initial, e)
			}
			// No syncMu, publishMu, m.mu, manager API, or goroutine handoff here.
			// This inline callback freezes the writer in the exact specified window.
			origin := time.Now()
			s.callback = func() {
				s.beginNS = time.Since(origin).Nanoseconds()
				defer func() { s.endNS = time.Since(origin).Nanoseconds() }()
				s.packets++
				s.verdict, _, s.err = p.Test(probe.Frame)
				var slot uint64
				if e := c.Maps["active_config"].Lookup(uint32(0), &slot); e != nil {
					s.err = e
					return
				}
				if slot > 1 {
					s.err = fmt.Errorf("invalid config selector %d", slot)
					return
				}
				if e := c.Maps[[]string{"config_a", "config_b"}[slot]].Lookup(uint32(ConfigRuleMapSelector), &s.selector); e != nil {
					s.err = e
				}
			}
			s.counting = true
			if kind == "a" {
				cidrBeforeAtomicPublishTestHook = func(*Handlers) { s.armed = true }
				defer func() { cidrBeforeAtomicPublishTestHook = nil }()
				flipAtomic(t, h, []Rule{next})
				cidrBeforeAtomicPublishTestHook = nil
			} else {
				h.commitStageTestHook = func(stage string) {
					if stage == "c-5" {
						s.armed = true
					}
				}
				defer func() { h.commitStageTestHook = nil }()
				flipCommit(t, h, flipDelta(t, h, []Rule{old}, []Rule{next}))
				h.commitStageTestHook = nil
			}
			shadow := s.side == 1-int(before)
			ok := s.calls == 1 && s.packets >= 1 && s.err == nil && s.selector == before && s.verdict == 1 && s.unarmedWrites == 0
			if kind == "a" {
				ok = ok && shadow
			}
			t.Logf("WW_%s_PRECONDITION pre_arm_writes=%d preset=commit kernel_receipt=1", kind, s.unarmedWrites)
			t.Logf("WW_%s_TIMING source=monotonic_since_origin begin_ns=%d end_ns=%d inline=1", kind, s.beginNS, s.endNS)
			t.Logf("WW_%s callbacks=%d packets=%d map=%s op=%s selector_before=%d selector_window=%d unflipped=%d shadow=%d verdict=%d pass=%d", kind, s.calls, s.packets, s.name, s.op, before, s.selector, flipBool(s.selector == before), flipBool(shadow), s.verdict, flipBool(ok))
			if !ok {
				t.Errorf("WW_%s_WINDOW err=%v pass=0", kind, s.err)
			}
			executed++
		})
	}
	if executed != 2 {
		t.Fatal("WW_EXEC count")
	}
	t.Logf("WW_VERDICT windows=%d pass=%d", executed, flipBool(!t.Failed()))
}

// Deliberately direct, small interval examples catch point-sampling mistakes.
func TestFlipTrafficIntervals(t *testing.T) {
	requests := []flipRequestRecord{{10, 20, 2}, {30, 40, 1}, {50, 60, 2}}
	cases := []struct {
		lo, hi int64
		want   int
	}{{-100, 9, 1}, {21, 29, 1}, {10, 20, 2}, {19, 51, 4}, {61, 100, 1}, {20, 20, 2}}
	for _, tc := range cases {
		n := 0
		for j := 0; j <= len(requests); j++ {
			if flipPossible(requests, j, flipPacketRecord{Start: tc.lo, End: tc.hi}) {
				n++
			}
		}
		if n != tc.want {
			t.Fatalf("FLIPTRAFFIC_INTERVAL [%d,%d] overlaps=%d want=%d", tc.lo, tc.hi, n, tc.want)
		}
	}
	t.Logf("FLIPTRAFFIC_INTERVAL cases=%d mismatches=0", len(cases))
}
