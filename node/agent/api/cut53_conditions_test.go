package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func cut53MemoryHandler(t *testing.T, rules ...Rule) *Handlers {
	t.Helper()
	h := &Handlers{rules: make(map[string]StoredRule), cidrRules: make(map[string]StoredCIDRRule), ruleKeyIndex: make(map[RuleKey]ruleIDSet), cidrRuleKeyIndex: make(map[CIDRRuleKey]ruleIDSet), logicalOwners: make(map[uint32]string), pendingLogicalIDs: make(map[uint32]bool), cidrMgr: cidr.NewManager(newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie())}
	for _, r := range rules {
		p, err := h.prepareAtomicRule(r)
		if err != nil {
			t.Fatal(err)
		}
		if p.IsCIDR {
			k := p.CIDR
			if p.Rule.SrcCIDR != "" {
				k.SrcID, err = h.cidrMgr.ReserveSrcID(p.Rule.SrcCIDR)
				if err != nil {
					t.Fatal(err)
				}
			}
			if p.Rule.DstCIDR != "" {
				k.DstID, err = h.cidrMgr.ReserveDstID(p.Rule.DstCIDR)
				if err != nil {
					t.Fatal(err)
				}
			}
			h.cidrRules[r.ID] = ruleToStoredCIDR(k, p.Rule.SrcCIDR, p.Rule.DstCIDR, p.Rule)
			addRuleID(h.cidrRuleKeyIndex, k, r.ID)
		} else {
			h.rules[r.ID] = ruleToStored(p.Exact, p.Rule)
			addRuleID(h.ruleKeyIndex, p.Exact, r.ID)
		}
		h.rememberLogicalIDLocked(r.ID, r.LogicalID)
	}
	return h
}
func cut53MemoryRouter(h *Handlers) *gin.Engine {
	r := gin.New()
	r.POST("/atomic", h.AtomicSync)
	return r
}
func cut53Request(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func cut53Pure(cidrKey bool, id string, logicalID uint32) Rule {
	r := Rule{ID: id, LogicalID: logicalID, SrcIP: "192.0.2.1", Protocol: "tcp", Action: "drop"}
	if cidrKey {
		r.SrcIP = ""
		r.SrcCIDR = "192.0.2.0/24"
	}
	return r
}
func cut53State(h *Handlers) string {
	return fmt.Sprintf("%#v/%#v/%#v/%#v/%#v/%#v/%#v/%#v", h.rules, h.cidrRules, h.ruleKeyIndex, h.cidrRuleKeyIndex, h.logicalOwners, h.pendingLogicalIDs, h.cidrMgr.ListSrcCIDRs(), h.cidrMgr.ListDstCIDRs())
}

func TestCut53ClassificationBeforeValidation(t *testing.T) {
	h := cut53MemoryHandler(t)
	for _, cidrKey := range []bool{false, true} {
		a := cut53Pure(cidrKey, "a", 1)
		b := a
		b.ID = "b"
		b.LogicalID = 2
		b.Action = "invalid"
		for _, reverse := range []bool{false, true} {
			items := []Rule{a, b}
			if reverse {
				items[0], items[1] = items[1], items[0]
			}
			_, err := h.preflightAtomicConditions(items)
			group, ok := err.(*atomicConditionGroupError)
			if !ok || len(group.Conflicts) != 2 {
				t.Fatalf("D5 lost invalid member cidr=%v reverse=%v: %v", cidrKey, reverse, err)
			}
			_, validation := h.prepareAtomicRule(b)
			for _, c := range group.Conflicts {
				if c.Reason != validation.Error() {
					t.Fatalf("D6 reason=%q want existing validator=%q", c.Reason, validation)
				}
			}
		}
	}
	// An unidentifiable key bypasses grouping and keeps its ordinary validation.
	invalid := Rule{ID: "bad", SrcIP: "invalid", TTL: cut4BString("")}
	groups, err := h.preflightAtomicConditions([]Rule{invalid})
	if err != nil || len(groups) != 0 {
		t.Fatalf("invalid key group=%v err=%v", groups, err)
	}
}

func TestCut53NormalizeAndWire(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"TTL", "128, 64", "64,128"}, {"DSCP", "3,2,1", "1-3"}, {"ICMPType", "8, 0", "0,8"}, {"ICMPCode", "3, 0", "0,3"}, {"Fragment", "nonfirst", "middle,last"}, {"PktLen", "200, 100-199", "100-200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := cut53Pure(false, "normalize", 17)
			r.Action = ""
			if strings.HasPrefix(tc.name, "ICMP") {
				r.Protocol = "icmp"
			}
			reflect.ValueOf(&r).Elem().FieldByName(tc.name).Set(reflect.ValueOf(cut4BString(tc.input)))
			h := &Handlers{}
			p, err := h.prepareAtomicRule(r)
			if err != nil {
				t.Fatal(err)
			}
			got := reflect.ValueOf(p.Rule).FieldByName(tc.name).Elem().String()
			if got != tc.want || p.Rule.Action != "drop" {
				t.Fatalf("I19 canonical=%q action=%q", got, p.Rule.Action)
			}
			row, err := EncodeConditionValue([]Rule{p.Rule})
			if err != nil {
				t.Fatal(err)
			}
			var oracle bytes.Buffer
			if err = binary.Write(&oracle, binary.LittleEndian, row); err != nil {
				t.Fatal(err)
			} // Same byte oracle as b1Wire.
			wire := conditionValueToBytes(row)
			if len(wire) != 844 || !bytes.Equal(wire, oracle.Bytes()) {
				t.Fatalf("condition wire differs from b1Wire for %s", tc.name)
			}
			r = p.Rule
			reflect.ValueOf(&r).Elem().FieldByName(tc.name).Set(reflect.ValueOf(cut4BString("")))
			if _, err = h.prepareAtomicRule(r); err == nil {
				t.Fatalf("empty %s accepted", tc.name)
			}
		})
	}
	r := cut53Pure(false, "flags", 17)
	r.TcpFlags = "SYN,!ACK"
	p, err := (&Handlers{}).prepareAtomicRule(r)
	if err != nil || p.Rule.TcpFlags != "!ACK,SYN" {
		t.Fatalf("I19 flags=%q err=%v", p.Rule.TcpFlags, err)
	}
	r.TcpFlags = "!SYN"
	p, err = (&Handlers{}).prepareAtomicRule(r)
	if err != nil {
		t.Fatal(err)
	}
	row, err := EncodeConditionValue([]Rule{p.Rule})
	if err != nil || row.TCPReq != 1 {
		t.Fatalf("W12 !SYN TCPReq=%d err=%v", row.TCPReq, err)
	}
	v := RuleValue{Action: ActionDrop, TcpFlagsMask: 255, TcpFlagsValue: 255, MatchAnomaly: 15, RateLimit: 33, PktLenMin: 1, PktLenMax: 65534, Pad2: [4]byte{1, 2, 3, 4}, LogicalID: 7, LogicalReserved: [12]byte{9}}
	b := ruleValueToBytes(v)
	if b[1] != 0 || b[2] != 0 || b[3] != 0 || binary.LittleEndian.Uint32(b[24:28]) != 0 || !bytes.Equal(b[28:32], []byte{1, 0, 0, 0}) {
		t.Fatalf("W11 old predicates/padding=%x", b)
	}
	if b[0] != ActionDrop || binary.LittleEndian.Uint32(b[4:8]) != 33 || binary.LittleEndian.Uint32(b[8:12]) != 7 || !bytes.Equal(b[12:24], make([]byte, 12)) {
		t.Fatalf("W11 unrelated rule bytes changed=%x", b)
	}
	if b[3] != 0 || b[28] != RuleHasConditions {
		t.Fatal("K16 flagged row retained legacy anomaly predicate")
	}
}
func TestCut53AnomalyNodeLimits(t *testing.T) {
	cells := 0
	for bits := uint8(1); bits <= 15; bits++ {
		for _, isCIDR := range []bool{false, true} {
			for _, v6 := range []bool{false, true} {
				r := cut53Pure(isCIDR, "anomaly", 17)
				r.MatchAnomaly = bits
				if v6 {
					if isCIDR {
						r.SrcCIDR = "2001:db8::/64"
					} else {
						r.SrcIP = "2001:db8::1"
					}
				}
				err := validateNodeAnomalyFields(bits, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR)
				if (err != nil) != (v6 && bits&9 != 0) {
					t.Fatalf("K9 bits=%x cidr=%v v6=%v err=%v", bits, isCIDR, v6, err)
				}
				cells++
			}
		}
	}
	for _, tc := range []struct {
		bits              uint8
		action, src, cidr string
	}{{16, "drop", "192.0.2.1", ""}, {8, "drop", "", ""}, {4, "drop", "", "0.0.0.0/0"}} {
		if err := validateNodeAnomalyFields(tc.bits, tc.action, tc.src, "", tc.cidr, ""); err == nil {
			t.Fatalf("K9 accepted invalid=%+v", tc)
		}
		cells++
	}
	if err := validateNodeAnomalyFields(4, "rate_limit", "192.0.2.1", "", "", ""); err != nil {
		t.Fatalf("K9 bounded anomaly + rate_limit must pass: %v", err)
	}
	cells++
	t.Logf("CUT53_K9 cells=%d", cells)
}
