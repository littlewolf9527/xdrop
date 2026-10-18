//go:build linux

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"golang.org/x/sys/unix"
)

// FF_FRAME_BEGIN: portable pure functions, also exercised by ffkit/selfcheck.py.
type ffFrameSpec struct {
	Family, Protocol, TTL int
	Src, Dst              string
}

func ffSpec(cell string) ffFrameSpec {
	s := ffFrameSpec{4, 6, 64, "10.10.9.9", "10.20.100.1"}
	switch cell {
	case "F-ex":
		s.Src = "10.10.2.1"
	case "F-cidr6":
		s.Family, s.Src, s.Dst = 6, "2001:db8:a::1", "2001:db8:b::1"
	case "F-cond-hit", "F-cond-miss":
		s.Src = "10.10.4.1"
		if cell == "F-cond-hit" {
			s.TTL = 5
		}
	case "F-rl":
		s.Src, s.Protocol = "10.10.3.1", 17
	case "F-crl":
		s.Src, s.Protocol = "10.10.7.1", 17
	case "F-wl":
		s.Src = "10.10.5.1"
	case "F-miss6":
		s.Family, s.Src, s.Dst = 6, "2001:db8:c::1", "2001:db8:b::1"
	case "F-map6":
		s.Family, s.Src, s.Dst = 6, "::ffff:10.10.2.1", "2001:db8:b::1"
	case "F-new":
		s.Src = "10.10.6.1"
	case "F-arp":
		s.Family, s.Protocol, s.TTL = 0, 0, 0
	}
	return s
}
func ffChecksum(b []byte) uint16 {
	var n uint32
	for i := 0; i < len(b); i += 2 {
		n += uint32(b[i]) << 8
		if i+1 < len(b) {
			n += uint32(b[i+1])
		}
	}
	for n>>16 != 0 {
		n = n&65535 + n>>16
	}
	return ^uint16(n)
}
func ffFrame(s ffFrameSpec, mark string, seq uint32) []byte {
	eth := []byte{2, 0, 0, 0, 0xaa, 0x0b, 2, 0, 0, 0, 0xaa, 0x0a, 8, 0}
	payload := append([]byte(mark), make([]byte, 4)...)
	binary.BigEndian.PutUint32(payload[len(mark):], seq)
	src, dst := net.ParseIP(s.Src), net.ParseIP(s.Dst)
	if s.Family == 0 {
		eth[12], eth[13] = 8, 6
		for i := 0; i < 6; i++ {
			eth[i] = 255
		}
		arp := make([]byte, 28)
		copy(arp, []byte{0, 1, 8, 0, 6, 4, 0, 1})
		copy(arp[8:14], eth[6:12])
		copy(arp[14:18], src.To4())
		copy(arp[24:28], dst.To4())
		return append(append(eth, arp...), payload...)
	}
	n := 20
	if s.Protocol == 17 {
		n = 8
	}
	l4 := make([]byte, n)
	binary.BigEndian.PutUint16(l4, 1234)
	binary.BigEndian.PutUint16(l4[2:], 80)
	checkAt := 16
	if s.Protocol == 6 {
		binary.BigEndian.PutUint32(l4[4:], seq)
		l4[12], l4[13], l4[14], l4[15] = 0x50, 2, 255, 255
	} else {
		checkAt = 6
		binary.BigEndian.PutUint16(l4[4:], uint16(n+len(payload)))
	}
	l4 = append(l4, payload...)
	ip, pseudo := make([]byte, 20), make([]byte, 12)
	if s.Family == 4 {
		ip[0], ip[8], ip[9] = 0x45, byte(s.TTL), byte(s.Protocol)
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		copy(ip[12:16], src.To4())
		copy(ip[16:20], dst.To4())
		binary.BigEndian.PutUint16(ip[10:], ffChecksum(ip))
		copy(pseudo, ip[12:20])
		pseudo[9] = byte(s.Protocol)
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(l4)))
	} else {
		eth[12], eth[13] = 0x86, 0xdd
		ip, pseudo = make([]byte, 40), make([]byte, 40)
		ip[0], ip[6], ip[7] = 0x60, byte(s.Protocol), byte(s.TTL)
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		copy(ip[8:24], src.To16())
		copy(ip[24:40], dst.To16())
		copy(pseudo, ip[8:40])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(l4)))
		pseudo[39] = byte(s.Protocol)
	}
	check := ffChecksum(append(pseudo, l4...))
	if check == 0 {
		check = 65535
	}
	binary.BigEndian.PutUint16(l4[checkAt:], check)
	return append(append(eth, ip...), l4...)
}

// Parse from wire offsets, independently of the constructor; verify all headers.
func ffParse(frame []byte) (ffFrameSpec, []byte, error) {
	s := ffFrameSpec{}
	bad := fmt.Errorf("invalid constructed frame")
	if len(frame) < 42 || !bytes.Equal(frame[6:12], []byte{2, 0, 0, 0, 0xaa, 0x0a}) {
		return s, nil, bad
	}
	kind, ip := binary.BigEndian.Uint16(frame[12:14]), frame[14:]
	if kind == 0x806 {
		if !bytes.Equal(frame[:6], bytes.Repeat([]byte{255}, 6)) || !bytes.Equal(ip[:8], []byte{0, 1, 8, 0, 6, 4, 0, 1}) || !bytes.Equal(ip[8:14], frame[6:12]) || !bytes.Equal(ip[18:24], make([]byte, 6)) {
			return s, nil, bad
		}
		s.Src, s.Dst = net.IP(ip[14:18]).String(), net.IP(ip[24:28]).String()
		return s, ip[28:], nil
	}
	if !bytes.Equal(frame[:6], []byte{2, 0, 0, 0, 0xaa, 0x0b}) {
		return s, nil, bad
	}
	var l4, pseudo []byte
	if kind == 0x800 && ip[0] == 0x45 && int(binary.BigEndian.Uint16(ip[2:4])) == len(ip) && ffChecksum(ip[:20]) == 0 {
		s = ffFrameSpec{4, int(ip[9]), int(ip[8]), net.IP(ip[12:16]).String(), net.IP(ip[16:20]).String()}
		l4, pseudo = ip[20:], make([]byte, 12)
		copy(pseudo, ip[12:20])
		pseudo[9] = byte(s.Protocol)
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(l4)))
	} else if kind == 0x86dd && len(ip) >= 40 && ip[0]>>4 == 6 && int(binary.BigEndian.Uint16(ip[4:6]))+40 == len(ip) {
		s = ffFrameSpec{6, int(ip[6]), int(ip[7]), net.IP(ip[8:24]).String(), net.IP(ip[24:40]).String()}
		l4, pseudo = ip[40:], make([]byte, 40)
		copy(pseudo, ip[8:40])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(l4)))
		pseudo[39] = byte(s.Protocol)
	} else {
		return s, nil, bad
	}
	if len(l4) < 8 || binary.BigEndian.Uint16(l4[:2]) != 1234 || binary.BigEndian.Uint16(l4[2:4]) != 80 || ffChecksum(append(pseudo, l4...)) != 0 {
		return s, nil, bad
	}
	if s.Protocol == 6 && len(l4) >= 20 && l4[12] == 0x50 && l4[13] == 2 {
		return s, l4[20:], nil
	}
	if s.Protocol == 17 && int(binary.BigEndian.Uint16(l4[4:6])) == len(l4) {
		return s, l4[8:], nil
	}
	return s, nil, bad
}

// FF_FRAME_END

var ffCells = strings.Fields("F-ex F-cidr6 F-cond-hit F-cond-miss F-rl F-wl F-miss4 F-miss6 F-arp F-map6 F-crl F-new")

func ffEmit(kind string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic("FF record encoding")
	}
	fmt.Printf("%s %s\n", kind, b)
}
func ffUTC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func ffAssert(t *testing.T, ok bool, message string) {
	t.Helper()
	if !ok {
		t.Errorf("FF assertion: %s", message)
	}
}
func ffExpect(scenario, phase, dir, cell string) (int, int, int) {
	n := 20
	if cell == "F-rl" || cell == "F-crl" {
		n = 50
	}
	if scenario == "hidx" || (scenario != "both" && dir == "lan_to_wan") {
		return n, n, n
	}
	if cell == "F-rl" || cell == "F-crl" {
		return n, 1, 49
	}
	if cell == "F-ex" || cell == "F-cidr6" || cell == "F-cond-hit" || cell == "F-map6" || cell == "F-new" || (cell == "F-wl" && phase != "P1") {
		return n, 0, 0
	}
	return n, n, n
}
func ffSocket(t *testing.T, name string) (int, *syscall.SockaddrLinklayer) {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require(t, err == nil, "owned interface lookup")
	// ETH_P_ALL is passed in network order, using NativeEndian on either lab architecture.
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], syscall.ETH_P_ALL)
	sa := &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: binary.NativeEndian.Uint16(protocol[:])}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(sa.Protocol))
	require(t, err == nil, "AF_PACKET socket")
	t.Cleanup(func() { syscall.Close(fd) })
	require(t, syscall.Bind(fd, sa) == nil, "AF_PACKET bind")
	require(t, syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20) == nil, "receive buffer")
	tv := syscall.NsecToTimeval((50 * time.Millisecond).Nanoseconds())
	require(t, syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv) == nil, "receive timeout")
	return fd, sa
}

// FF_CAPTURE_BEGIN: pure capture validation, also exercised by ffkit/selfcheck.py.
type ffSentFrames struct {
	mu     sync.Mutex
	frames map[uint32][]byte
}

func (s *ffSentFrames) send(seq uint32, frame []byte, send func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frames == nil {
		s.frames = map[uint32][]byte{}
	}
	// Publish an immutable copy before Sendto. Readers wait for its result under
	// the same mutex, so a failed send is removed before it can be received.
	s.frames[seq] = append([]byte(nil), frame...)
	err := send()
	if err != nil {
		delete(s.frames, seq)
	}
	return err
}
func (s *ffSentFrames) frame(seq uint32) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	frame, ok := s.frames[seq]
	return frame, ok
}

type ffCapture struct {
	got                                map[uint32]bool
	equal, duplicates, errors, invalid int
	started, last, ended               time.Time
	maxGap                             time.Duration
	drops                              uint32
	statsOK                            bool
}

// selfcheck compares these vocabularies with the actual phase/direction send
// sites. Cells use ffCells directly, the same source as the phase sender.
var ffCapturePhases = strings.Fields("P1 P2 P3 P4a S P4c P1h P1u-before P1u-after")
var ffCaptureDirs = strings.Fields("wan_to_lan lan_to_wan")

func ffOtherMark(frame []byte, mark string) bool {
	current := strings.Split(mark, "|")
	if len(current) != 6 || current[0] != "FF1" || current[5] != "" {
		return false
	}
	has := func(values []string, want string) bool {
		for _, value := range values {
			if value == want {
				return true
			}
		}
		return false
	}
	for _, cell := range ffCells {
		spec := ffSpec(cell)
		// Empty mark leaves only the four sequence bytes after the fixed headers.
		start := len(ffFrame(spec, "", 0)) - 4
		if start >= len(frame) {
			continue
		}
		parts := strings.SplitN(string(frame[start:]), "|", 6)
		if len(parts) == 6 && parts[0] == "FF1" && parts[1] == current[1] && has(ffCapturePhases, parts[2]) && has(ffCaptureDirs, parts[3]) && has(ffCells, parts[4]) && parts[4] == cell &&
			(parts[2] != current[2] || parts[3] != current[3] || parts[4] != current[4]) {
			other := strings.Join(parts[:5], "|") + "|"
			seqAt := start + len(other)
			if seqAt+4 > len(frame) {
				continue
			}
			want := ffFrame(spec, other, binary.BigEndian.Uint32(frame[seqAt:seqAt+4]))
			if len(frame) >= len(want) && bytes.Equal(frame[:len(want)], want) && bytes.Count(frame[len(want):], []byte{0}) == len(frame)-len(want) {
				return true
			}
		}
	}
	return false
}

func (r *ffCapture) accept(frame []byte, mark string, sent *ffSentFrames) {
	pos := bytes.Index(frame, []byte(mark))
	if pos < 0 {
		if ffOtherMark(frame, mark) {
			return
		}
		if len(frame) >= 12 && bytes.Equal(frame[6:12], []byte{2, 0, 0, 0, 0xaa, 0x0a}) {
			r.invalid++
		}
		return
	}
	if pos+len(mark)+4 > len(frame) {
		r.invalid++
		return
	}
	seq := binary.BigEndian.Uint32(frame[pos+len(mark):])
	want, ok := sent.frame(seq)
	if !ok {
		r.invalid++
		return
	}
	equal := len(frame) >= len(want) && bytes.Equal(frame[:len(want)], want) && bytes.Count(frame[len(want):], []byte{0}) == len(frame)-len(want)
	if !equal {
		r.invalid++
	}
	r.last = time.Now()
	if r.got[seq] {
		r.duplicates++
		return
	}
	r.got[seq] = true
	if equal {
		r.equal++
	}
}

// FF_CAPTURE_END

func ffReceiver(fd int, stream bool, mark string, sent *ffSentFrames, stop <-chan struct{}, ready chan<- time.Time, done chan<- ffCapture) {
	r := ffCapture{got: map[uint32]bool{}, started: time.Now()}
	if stream {
		_, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		r.statsOK = err == nil
	}
	ready <- r.started
	previous := r.started
	buf := make([]byte, 65536)
	for {
		now := time.Now()
		if gap := now.Sub(previous); gap > r.maxGap {
			r.maxGap = gap
		}
		previous = now
		select {
		case <-stop:
			if stream {
				stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
				r.statsOK = r.statsOK && err == nil
				if err == nil {
					r.drops = stats.Drops
				}
			}
			r.ended = time.Now()
			done <- r
			return
		default:
		}
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			r.errors++
			continue
		}
		addr, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || addr.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		r.accept(buf[:n], mark, sent)
	}
}

type ffLab struct {
	t                                  *testing.T
	scenario, base, logs               string
	direct                             *nc.Client
	agent                              *labProcess
	controller                         *labProcess
	controllerBinary, controllerConfig string
	pairs                              map[string]ffPairSelection
	rules                              map[string]nc.Rule
	wl                                 []nc.Entry
	tx, rx                             map[string]int
	address                            map[string]*syscall.SockaddrLinklayer
}

func (f *ffLab) call(method, path, body string, status int) []byte {
	b, code, _, _, err := labRaw(f.base, method, path, labAccount(f.base).cookie, "", body, nil)
	require(f.t, err == nil && code == status, "controller fixture request", method, path, code)
	return b
}
func (f *ffLab) add(name, body string) {
	b := f.call("POST", "/rules", body, 201)
	var receipt CreateResponse
	var rule nc.Rule
	require(f.t, json.Unmarshal(b, &receipt) == nil && receipt.ID != "" && receipt.LogicalID > 0 && !receipt.Existing, "create receipt")
	require(f.t, json.Unmarshal([]byte(body), &rule) == nil, "rule fixture")
	rule.ID, rule.LogicalID = receipt.ID, uint32(receipt.LogicalID)
	if rule.Protocol == "" {
		rule.Protocol = "all"
	}
	f.rules[name] = rule
}
func (f *ffLab) readRules() (map[string]nc.ReadRule, bool) {
	got := map[string]nc.ReadRule{}
	pages, total := 1, 0
	for page := 1; page <= pages; page++ {
		r, err := f.direct.Rules(context.Background(), page, 2)
		if err != nil || r.Pagination.Page != page || r.Pagination.Pages > 10 {
			return got, false
		}
		pages, total = r.Pagination.Pages, r.Pagination.Total
		for _, rule := range r.Rules {
			if _, dup := got[rule.ID]; dup {
				return got, false
			}
			got[rule.ID] = rule
		}
	}
	return got, len(got) == total
}
func (f *ffLab) stats() (map[string]any, bool) {
	s, err := f.direct.Stats(context.Background())
	return s, err == nil
}
func ffNumber(m map[string]any, key string) (int64, bool) {
	v, ok := m[key].(json.Number)
	n, err := v.Int64()
	return n, ok && err == nil && n >= 0
}
func (f *ffLab) selector() (int64, bool) {
	s, ok := f.stats()
	a, valid := s["agent_state"].(map[string]any)
	n, found := ffNumber(a, "rule_map_selector")
	return n, ok && valid && found && (n == 0 || n == 1)
}
func (f *ffLab) wait(selector *int64) time.Time {
	var healthy time.Time
	labWait(f.t, 60*time.Second, func() bool {
		h, err := f.direct.Health(context.Background())
		if err != nil || (f.scenario != "hidx" && h.Status != "healthy") {
			return false
		}
		if healthy.IsZero() {
			healthy = time.Now()
		}
		if f.scenario == "hidx" {
			return true
		}
		r, ok := f.readRules()
		if !ok || len(r) != len(f.rules) {
			return false
		}
		for _, want := range f.rules {
			if !reflect.DeepEqual(r[want.ID].Rule, want) {
				return false
			}
		}
		w, e := f.direct.Whitelist(context.Background())
		if e != nil || w.Count != len(f.wl) || len(w.Entries) != len(f.wl) {
			return false
		}
		for i := range f.wl {
			if w.Entries[i] != f.wl[i] {
				return false
			}
		}
		if selector != nil {
			n, ok := f.selector()
			return ok && n != *selector
		}
		return true
	})
	return healthy
}

// FF_PAIR_BEGIN: shared with the portable selected-binary selfcheck.
func ffPair(agent, controller, manifest, want string) bool {
	var entries map[string]struct{ Source, SHA string }
	raw, err := os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, path := range []string{agent, controller} {
		if path == "" {
			continue
		}
		selected, err := os.ReadFile(path)
		entry, ok := entries[path]
		if err != nil || !ok || entry.Source != want || fmt.Sprintf("%x", sha256.Sum256(selected)) != entry.SHA {
			return false
		}
	}
	return agent != ""
}

// FF_PAIR_END
type ffPairSelection struct {
	agent, config, controller, source string
	agentSHA, controllerSHA           string
	paired                            bool
}

// Precompute both generations before any packet sender or receiver starts.
func (f *ffLab) preparePairs() {
	f.pairs = make(map[string]ffPairSelection, 2)
	for _, label := range []string{"P0", "S"} {
		controller := f.controllerBinary
		if f.scenario == "upg" && label == "S" {
			controller = os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		}
		binary, cfg := os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG")
		if f.scenario == "ctl" || (f.scenario == "upg" && label == "P0") {
			binary, cfg = os.Getenv("XDROP_FF_BASELINE_AGENT"), os.Getenv("XDROP_FF_BASELINE_CONFIG")
		}
		want := os.Getenv("XDROP_FF_SOURCE_HEAD") + "+ns"
		if f.scenario == "ctl" {
			want = "d39805f4910e4245004cf1157056c0ad749ef379"
		} else if f.scenario == "upg" && label == "P0" {
			want = "b9e06b79fe384aba783c692ec88bad3164c81683"
		}
		paired := ffPair(binary, controller, os.Getenv("XDROP_FF_GENERATIONS"), want)
		agentBytes, _ := os.ReadFile(binary)
		controllerBytes, _ := os.ReadFile(controller)
		f.pairs[label] = ffPairSelection{binary, cfg, controller, want, fmt.Sprintf("%x", sha256.Sum256(agentBytes)), fmt.Sprintf("%x", sha256.Sum256(controllerBytes)), paired}
	}
}

func (f *ffLab) writeCurrentConfig() {
	root := filepath.Dir(f.controllerConfig)
	text := "listen: " + strings.TrimPrefix(f.base, "http://") + "\ndatabase: " + filepath.Join(root, "controller.db") + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
	require(f.t, os.WriteFile(f.controllerConfig, []byte(text), 0600) == nil, "new generation configuration")
	labNodeInit(f.t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), f.controllerConfig, "lab", os.Getenv("XDROP_CTLCUT2_AGENT_URL"), os.Getenv("XDROP_CTLCUT2_KEY_FILE"))
}

func (f *ffLab) startController(binary string, initial bool) {
	previous := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
	selected := ""
	if initial {
		selected = binary
	}
	if initial && (f.scenario == "ctl" || f.scenario == "upg") {
		labLegacyDatabase = filepath.Join(filepath.Dir(f.controllerConfig), "controller.db")
		defer func() { labLegacyDatabase = "" }()
	}
	f.t.Setenv("XDROP_CTLCUT3_CONTROLLER", selected)
	f.controller = labProcessStart(f.t, binary, f.controllerConfig, filepath.Join(f.logs, "controller-"+fmt.Sprint(initial)+".log"))
	f.t.Setenv("XDROP_CTLCUT3_CONTROLLER", previous)
	f.controllerBinary = binary
}

func (f *ffLab) start(label string) time.Time {
	before := time.Now()
	if f.scenario == "upg" && label != "P0" {
		require(f.t, f.controller.cmd.Process.Signal(syscall.SIGTERM) == nil, "controller SIGTERM")
		select {
		case err := <-f.controller.done:
			f.controller.stopped = true
			require(f.t, err == nil, "controller exit")
		case <-time.After(30 * time.Second):
			f.t.Fatal("controller exit deadline")
		}
		f.writeCurrentConfig()
		f.startController(os.Getenv("XDROP_CTLCUT3_CONTROLLER"), false)
	}
	pair := f.pairs[label]
	ffEmit("FFPAIR", map[string]any{"scenario": f.scenario, "phase": label, "source": pair.source, "agent": pair.agent, "controller": pair.controller, "selected_sha_match": pair.paired, "agent_sha": pair.agentSHA, "controller_sha": pair.controllerSHA})
	ffAssert(f.t, pair.paired, "selected agent/controller generation prerequisite")
	f.agent = labProcessStart(f.t, pair.agent, pair.config, filepath.Join(f.logs, label+"-agent.log"))
	ownMount, e1 := os.Readlink("/proc/self/ns/mnt")
	agentMount, e2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", f.agent.cmd.Process.Pid))
	sameMount := e1 == nil && e2 == nil && ownMount == agentMount
	ffEmit("FFALIVE", map[string]any{"scenario": f.scenario, "event": "start", "pid": f.agent.cmd.Process.Pid, "t_utc": ffUTC(time.Now()), "start_before_utc": ffUTC(before), "alive": true, "same_mount": sameMount})
	require(f.t, sameMount, "agent/test private mount namespace")
	return before
}
func (f *ffLab) stop() time.Time {
	sigterm := time.Now()
	require(f.t, f.agent.cmd.Process.Signal(syscall.SIGTERM) == nil, "agent SIGTERM")
	select {
	case err := <-f.agent.done:
		f.agent.stopped = true
		require(f.t, err == nil, "agent exit")
	case <-time.After(30 * time.Second):
		f.t.Fatal("agent exit deadline")
	}
	return sigterm
}
func ffLinks(t *testing.T) []map[string]any {
	var rows []map[string]any
	for _, name := range []string{"w0", "l0"} {
		b, err := exec.Command("ip", "-j", "-details", "link", "show", "dev", name).Output()
		var raw []struct {
			Flags []string       `json:"flags"`
			XDP   map[string]any `json:"xdp"`
		}
		require(t, err == nil && json.Unmarshal(b, &raw) == nil && len(raw) == 1, "owned link snapshot")
		rows = append(rows, map[string]any{"name": name, "promisc": strings.Contains("|"+strings.Join(raw[0].Flags, "|")+"|", "|PROMISC|"), "xdp": len(raw[0].XDP) > 0})
	}
	return rows
}
func (f *ffLab) shape() {
	s, valid := f.stats()
	// Explicit JSON names are needed for attach_mode.
	b, _ := json.Marshal(s["xdp_info"])
	var info struct {
		Mode       string `json:"mode"`
		Interfaces []struct {
			Name       string `json:"name"`
			Role       string `json:"role"`
			AttachMode string `json:"attach_mode"`
		} `json:"interfaces"`
	}
	ok := valid && json.Unmarshal(b, &info) == nil && info.Mode == "fast_forward" && len(info.Interfaces) == 2
	roles := map[string]string{"w0": "inbound", "l0": "outbound"}
	for _, item := range info.Interfaces {
		ok = ok && roles[item.Name] == item.Role && item.AttachMode == "generic"
		delete(roles, item.Name)
	}
	links := ffLinks(f.t)
	h, err := f.direct.Health(context.Background())
	ok = ok && len(roles) == 0 && links[0]["promisc"] == true && links[1]["promisc"] == true && err == nil && (f.scenario == "hidx" || h.Status == "healthy")
	ffEmit("FFSHAPE", map[string]any{"scenario": f.scenario, "phase": "P0", "xdp_info": info, "links": links, "healthy": err == nil && h.Status == "healthy", "api_ready": err == nil, "pass": ok})
	ffAssert(f.t, ok, "P0 shape")
}
func (f *ffLab) snapshot() (map[string]int64, bool) {
	out := map[string]int64{}
	r, ok := f.readRules()
	for name, want := range f.rules {
		v, valid := ffNumber(r[want.ID].Stats, "match_count")
		out[name+".match_count"], ok = v, ok && valid
	}
	s, valid := f.stats()
	ok = ok && valid
	for _, name := range []string{"whitelisted_packets", "mapped_v6_dropped", "rate_limited_packets"} {
		v, valid := ffNumber(s, name)
		out[name], ok = v, ok && valid
	}
	return out, ok
}
func (f *ffLab) cell(phase, dir, cell string) (int, bool) {
	n, low, high := ffExpect(f.scenario, phase, dir, cell)
	if cell == "F-rl" || cell == "F-crl" {
		time.Sleep(2500 * time.Millisecond)
	}
	mark := "FF1|" + f.scenario + "|" + phase + "|" + dir + "|" + cell + "|"
	stop, ready, done := make(chan struct{}), make(chan time.Time, 1), make(chan ffCapture, 1)
	sentFrames := &ffSentFrames{}
	go ffReceiver(f.rx[dir], false, mark, sentFrames, stop, ready, done)
	<-ready
	sent, first, last := 0, time.Time{}, time.Time{}
	frames := make([][]byte, n)
	for i := range frames {
		frames[i] = ffFrame(ffSpec(cell), mark, uint32(i))
	}
	start := time.Now()
	for i, frame := range frames {
		if sentFrames.send(uint32(i), frame, func() error { return syscall.Sendto(f.tx[dir], frame, 0, f.address[dir]) }) == nil {
			last = time.Now()
			if first.IsZero() {
				first = last
			}
			sent++
		}
	}
	burst := time.Since(start)
	time.Sleep(500 * time.Millisecond)
	close(stop)
	r := <-done
	received := len(r.got)
	valid := sent == n && r.errors == 0 && r.duplicates == 0 && r.invalid == 0 && received == r.equal && ((cell != "F-rl" && cell != "F-crl") || burst <= 200*time.Millisecond)
	ok := valid && received >= low && received <= high
	ffEmit("FFCELL", map[string]any{"scenario": f.scenario, "phase": phase, "dir": dir, "cell": cell, "sent": sent, "received": received, "byte_equal": r.equal, "expect": []int{low, high}, "pass": ok, "fixture_valid": valid, "invalid_frames": r.invalid, "burst_ms": float64(burst) / float64(time.Millisecond), "receive_errors": r.errors, "duplicates": r.duplicates, "t_first_send_utc": ffUTC(first), "t_last_recv_utc": ffUTC(r.last), "t_complete_utc": ffUTC(time.Now())})
	if !f.agent.stopped {
		ffEmit("FFALIVE", map[string]any{"scenario": f.scenario, "phase": phase, "pid": f.agent.cmd.Process.Pid, "t_utc": ffUTC(time.Now()), "alive": f.agent.cmd.Process.Signal(syscall.Signal(0)) == nil})
	}
	ffAssert(f.t, ok, phase+" "+dir+" "+cell)
	return received, valid
}
func (f *ffLab) phase(phase string) {
	cells := ffCells
	if phase == "P1" {
		cells = ffCells[:11]
	}
	if phase == "P4a" {
		cells = []string{"F-ex", "F-miss4", "F-arp"}
	}
	if phase == "P1h" || strings.HasPrefix(phase, "P1u-") {
		cells = []string{"F-ex", "F-miss4", "F-arp"}
		if phase == "P1h" {
			cells = []string{"F-miss4", "F-miss6", "F-arp"}
		}
		for _, dir := range []string{"wan_to_lan", "lan_to_wan"} {
			for _, cell := range cells {
				f.cell(phase, dir, cell)
			}
		}
		return
	}
	before, readOK := map[string]int64{}, true
	if phase != "P4a" {
		before, readOK = f.snapshot()
	}
	dropped, captureOK := 0, true
	for _, dir := range []string{"wan_to_lan", "lan_to_wan"} {
		for _, cell := range cells {
			received, valid := f.cell(phase, dir, cell)
			if (cell == "F-rl" || cell == "F-crl") && (f.scenario == "both" || dir == "wan_to_lan") {
				dropped += 50 - received
				captureOK = captureOK && valid
			}
		}
	}
	if phase == "P4a" {
		return
	}
	after, ok := f.snapshot()
	factor := int64(1)
	if f.scenario == "both" {
		factor = 2
	}
	want := map[string]int64{"R-ex.match_count": 20 * factor, "R-cidr6.match_count": 20 * factor, "R-cond.match_count": 20 * factor, "R-rl.match_count": 50 * factor, "R-crl.match_count": 50 * factor, "whitelisted_packets": 0, "mapped_v6_dropped": 20 * factor, "rate_limited_packets": int64(dropped)}
	if phase == "P1" {
		want["whitelisted_packets"] = 20 * factor
	} else {
		want["R-wl.match_count"], want["R-new.match_count"] = 20*factor, 20*factor
	}
	items := make([]string, 0, len(want))
	for item := range want {
		items = append(items, item)
	}
	sort.Strings(items)
	for _, item := range items {
		delta := after[item] - before[item]
		valid := readOK && ok && (item != "rate_limited_packets" || captureOK)
		pass := valid && delta == want[item]
		ffEmit("FFCOUNT", map[string]any{"scenario": f.scenario, "phase": phase, "item": item, "before": before[item], "after": after[item], "delta": delta, "expect": want[item], "pass": pass, "measurement_valid": valid})
		ffAssert(f.t, pass, phase+" "+item)
	}
}

func (f *ffLab) gap() {
	mark, spec := "FF1|"+f.scenario+"|S|wan_to_lan|F-miss4|", ffSpec("F-miss4")
	fd, _ := ffSocket(f.t, "l1") // S owns its socket; P4a has independent frame copies.
	stopRX, ready, rxDone := make(chan struct{}), make(chan time.Time, 1), make(chan ffCapture, 1)
	sentFrames := &ffSentFrames{}
	go ffReceiver(fd, true, mark, sentFrames, stopRX, ready, rxDone)
	rxStart := <-ready
	type sentRecord struct {
		seq uint32
		at  time.Time
	}
	var sent []sentRecord
	failures := 0
	var txStart time.Time
	stopTX, txDone, first := make(chan struct{}), make(chan struct{}), make(chan time.Time, 1)
	go func() {
		txStart = time.Now()
		defer close(txDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for seq := uint32(0); ; seq++ {
			frame := ffFrame(spec, mark, seq)
			if sentFrames.send(seq, frame, func() error { return syscall.Sendto(f.tx["wan_to_lan"], frame, 0, f.address["wan_to_lan"]) }) == nil {
				at := time.Now()
				sent = append(sent, sentRecord{seq, at})
				if len(sent) == 1 {
					first <- at
				}
			} else {
				failures++
			}
			select {
			case <-stopTX:
				return
			case <-ticker.C:
			}
		}
	}()
	// Also stop both goroutines on a fatal setup failure.
	defer func() {
		select {
		case <-stopTX:
		default:
			close(stopTX)
		}
		<-txDone
		select {
		case <-stopRX:
		default:
			close(stopRX)
		}
	}()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
	}
	time.Sleep(100 * time.Millisecond)
	sigterm := f.stop()
	post := ffLinks(f.t)
	promisc, xdp := post[0]["promisc"] == true && post[1]["promisc"] == true, post[0]["xdp"] == true && post[1]["xdp"] == true
	checked := f.scenario == "inb" || f.scenario == "both" || f.scenario == "hidx"
	ffEmit("FFPOSTTERM", map[string]any{"scenario": f.scenario, "links": post, "agent_exited": f.agent.stopped, "checked": checked, "promisc": promisc, "xdp": xdp})
	if checked {
		ffAssert(f.t, promisc, "post SIGTERM PROMISC")
		ffAssert(f.t, xdp, "post SIGTERM XDP")
	}
	if f.scenario == "inb" || f.scenario == "both" {
		f.phase("P4a")
	}
	f.start("S")
	readyAt := f.wait(nil)
	time.Sleep(time.Until(readyAt.Add(2100 * time.Millisecond)))
	close(stopTX)
	<-txDone
	time.Sleep(time.Second)
	close(stopRX)
	r := <-rxDone
	firstAt, lastAt, firstReceived, lastReceived := time.Time{}, time.Time{}, time.Time{}, time.Time{}
	maxGap := time.Duration(0)
	windowSent, received, outside := 0, 0, 0
	for i, item := range sent {
		if i == 0 {
			firstAt = item.at
		} else if gap := item.at.Sub(lastAt); gap > maxGap {
			maxGap = gap
		}
		lastAt = item.at
		inWindow := !item.at.Before(sigterm) && !item.at.After(readyAt)
		if inWindow {
			windowSent++
		}
		if r.got[item.seq] {
			received++
			if firstReceived.IsZero() {
				firstReceived = item.at
			}
			lastReceived = item.at
		} else if !inWindow {
			outside++
		}
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	// 墙上时钟（去掉单调读数）：runner 用序列化的 UTC 时间戳重算本值并比 0.01 ms，单调钟在 NTP 微调下会差出几十 µs。
	windowMS := ms(readyAt.Round(0).Sub(sigterm.Round(0)))
	pre, postFrame := !firstReceived.IsZero() && firstReceived.Before(sigterm), lastReceived.After(readyAt.Add(2*time.Second))
	coverage := !rxStart.After(firstAt) && !r.ended.Before(lastAt.Add(time.Second))
	base := len(sent) > 0 && failures == 0 && firstAt.Before(sigterm) && lastAt.After(readyAt.Add(2*time.Second)) && !txStart.IsZero() && !rxStart.IsZero() && r.errors == 0 && r.invalid == 0 && r.duplicates == 0 && len(r.got) == r.equal
	validity := []bool{maxGap <= 20*time.Millisecond, float64(windowSent) >= 0.5*windowMS, coverage && pre && postFrame, outside == 0, r.statsOK && r.drops == 0 && r.maxGap <= 100*time.Millisecond}
	lost := len(sent) - received
	// 所有者 10-15：包到了就算过 ⇒ 发送间隔 validity[0] 只记录不判；漏计丢失由切换窗口发包量 validity[1] 守。
	pass := base && validity[1] && validity[2] && validity[4] && lost == 0
	if f.scenario == "ctl" {
		pass = base && validity[1] && validity[2] && validity[3] && validity[4] && lost > 0
	}
	ffEmit("FFSTREAM", map[string]any{"scenario": f.scenario, "sent_unique": len(sent), "received_unique": received, "lost": lost, "send_failures": failures, "max_send_gap_ms": ms(maxGap), "window_sent": windowSent, "window_ms": windowMS, "t_first_send_utc": ffUTC(firstAt), "t_last_send_utc": ffUTC(lastAt), "sigterm_utc": ffUTC(sigterm), "ready_utc": ffUTC(readyAt), "tx_started_utc": ffUTC(txStart), "rx_started_utc": ffUTC(rxStart), "rx_ended_utc": ffUTC(r.ended), "pre_received": pre, "post_received": postFrame, "first_received_send_utc": ffUTC(firstReceived), "last_received_send_utc": ffUTC(lastReceived), "lost_outside_window": outside, "loss_localized": outside == 0, "tp_drops": r.drops, "stats_ok": r.statsOK, "max_receive_gap_ms": ms(r.maxGap), "receive_errors": r.errors, "invalid_frames": r.invalid, "duplicates": r.duplicates, "byte_equal": r.equal, "validity": validity, "base_valid": base, "pass": pass})
	ffAssert(f.t, pass, "S loss and validity")
}

// N3 records a real startup failure instead of fabricating six unexecuted cells.
func (f *ffLab) hidxFailure() {
	started, healthSeen := time.Now(), false
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case err := <-f.agent.done:
			f.agent.stopped = true
			raw, readErr := os.ReadFile(filepath.Join(f.logs, "P0-agent.log"))
			code := 0
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			}
			loaded := strings.Contains(string(raw), "CIDR manager initialized")
			devmapFailure := false
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "Failed to setup devmap:") && strings.Contains(line, "key too big for map") {
					devmapFailure = true
				}
			}
			witness := readErr == nil && code > 0 && time.Since(started) <= 30*time.Second && loaded && devmapFailure && !healthSeen
			ffEmit("FFHIDX", map[string]any{"scenario": f.scenario, "witness": "HIDX_START_FAIL", "exit": code, "within_30s": time.Since(started) <= 30*time.Second, "loaded": loaded, "devmap_e2big": devmapFailure, "health_seen": healthSeen, "pass": witness})
			ffAssert(f.t, false, "hidx startup must succeed")
			return
		case <-deadline.C:
			ffEmit("FFHIDX", map[string]any{"scenario": f.scenario, "witness": "HIDX_START_FAIL", "pass": false})
			f.t.Error("hidx mutation startup deadline")
			return
		case <-time.After(10 * time.Millisecond):
			_, err := f.direct.Health(context.Background())
			healthSeen = healthSeen || err == nil
		}
	}
}

func TestFFLab(t *testing.T) {
	if os.Getenv("XDROP_FF_LAB") == "" {
		t.Skip("requires owned FF lab namespaces and binaries")
	}
	scenario := os.Getenv("XDROP_FF_SCENARIO")
	require(t, scenario == "inb" || scenario == "both" || scenario == "hidx" || scenario == "upg" || scenario == "ctl", "FF scenario")
	for _, cell := range ffCells {
		want := ffSpec(cell)
		frame := ffFrame(want, "FF-SELF|", 7)
		got, payload, err := ffParse(frame)
		// net.IP.String canonicalizes mapped IPv6 to dotted IPv4; family remains 6.
		want.Src, want.Dst = net.ParseIP(want.Src).String(), net.ParseIP(want.Dst).String()
		require(t, err == nil && got == want && bytes.Equal(payload, append([]byte("FF-SELF|"), 0, 0, 0, 7)), "frame construction selfcheck", cell)
	}
	root := t.TempDir()
	f := &ffLab{t: t, scenario: scenario, base: os.Getenv("XDROP_CTLCUT3_URL"), logs: os.Getenv("XDROP_CTLCUT2_LOG_DIR"), rules: map[string]nc.Rule{}, tx: map[string]int{}, rx: map[string]int{}, address: map[string]*syscall.SockaddrLinklayer{}}
	keyfile := os.Getenv("XDROP_CTLCUT2_KEY_FILE")
	key, err := os.ReadFile(keyfile)
	require(t, err == nil && len(key) > 0, "private node key")
	agentURL := os.Getenv("XDROP_CTLCUT2_AGENT_URL")
	f.direct, err = nc.New(nc.NodeSpec{Name: "lab", BaseURL: agentURL, Key: nc.Secret(strings.TrimSpace(string(key)))}, nc.Options{})
	require(t, err == nil, "node client")
	var wl nc.Entry
	if scenario != "hidx" {
		config := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(f.base, "http://") + "\ndatabase: " + filepath.Join(root, "controller.db") + "\nnodes:\n - name: lab\n   url: " + agentURL + "\n   api_key_file: " + keyfile + "\n"
		require(t, os.WriteFile(config, []byte(text), 0600) == nil, "controller configuration")
		f.controllerConfig = config
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		if scenario == "ctl" || scenario == "upg" {
			binary = os.Getenv("XDROP_FF_BASELINE_CONTROLLER")
		}
		if scenario != "ctl" && scenario != "upg" {
			f.writeCurrentConfig()
		}
		f.startController(binary, true)
		for _, item := range [][2]string{
			{"R-ex", `{"src_ip":"10.10.2.1","dst_ip":"10.20.100.1","protocol":"tcp","dst_port":80,"action":"drop"}`},
			{"R-cidr6", `{"src_cidr":"2001:db8:a::/48","action":"drop"}`},
			{"R-cond", `{"src_ip":"10.10.4.1","protocol":"tcp","ttl":"1-10","action":"drop"}`},
			{"R-rl", `{"src_ip":"10.10.3.1","protocol":"udp","action":"rate_limit","rate_limit":5}`},
			{"R-crl", `{"src_cidr":"10.10.7.0/24","protocol":"udp","action":"rate_limit","rate_limit":5}`},
			{"R-wl", `{"src_ip":"10.10.5.1","protocol":"tcp","action":"drop"}`},
		} {
			f.add(item[0], item[1])
		}
		b := f.call("POST", "/whitelist", `{"src_ip":"10.10.5.1","protocol":"tcp"}`, 201)
		require(t, json.Unmarshal(b, &wl) == nil && wl.ID != "", "whitelist receipt")
		f.wl = []nc.Entry{wl}
	}
	f.preparePairs()
	f.start("P0")
	if scenario == "hidx" && os.Getenv("XDROP_FF_MUTATION") == "N3" {
		f.hidxFailure()
		return
	}
	f.wait(nil)
	f.shape()
	for _, item := range [][3]string{{"wan_to_lan", "w1", "l1"}, {"lan_to_wan", "l1", "w1"}} {
		f.tx[item[0]], f.address[item[0]] = ffSocket(t, item[1])
		f.rx[item[0]], _ = ffSocket(t, item[2])
	}
	if scenario == "hidx" {
		f.phase("P1h")
		f.gap()
		ffEmit("FFHIDX", map[string]any{"scenario": scenario, "witness": "HIDX_FORWARD", "pass": !t.Failed()})
	} else if scenario == "upg" || scenario == "ctl" {
		f.phase("P1u-before")
		f.gap()
		f.wait(nil)
		f.phase("P1u-after")
	} else {
		f.phase("P1")
		s0, ok := f.selector()
		require(t, ok, "P2 selector before")
		f.add("R-new", `{"src_ip":"10.10.6.1","protocol":"tcp","action":"drop"}`)
		f.call("DELETE", "/whitelist/"+wl.ID, "", 204)
		f.wl = nil
		f.wait(nil)
		s1, ok := f.selector()
		require(t, ok, "P2 selector after")
		ffEmit("FFSELECTOR", map[string]any{"scenario": scenario, "phase": "P2", "before": s0, "after": s1})
		f.phase("P2")
		s0, ok = f.selector()
		require(t, ok, "P3 selector before")
		f.call("POST", "/nodes/lab/sync", "", 202)
		f.wait(&s0)
		s1, ok = f.selector()
		require(t, ok && s0 != s1, "P3 atomic publication")
		ffEmit("FFSELECTOR", map[string]any{"scenario": scenario, "phase": "P3", "before": s0, "after": s1})
		f.phase("P3")
		f.gap()
		f.wait(nil)
		f.phase("P4c")
	}
	f.stop()
	ffEmit("FFPOST", map[string]any{"scenario": scenario, "phase": "P4", "agent_exited": f.agent.stopped, "links": ffLinks(t)})
	if scenario != "hidx" {
		for _, path := range []string{"/system", "/nodes"} {
			f.call("GET", path, "", 200)
		}
		labAccountScan(t)
	}
	ffEmit("FFEND", map[string]any{"scenario": scenario, "complete": true})
}
