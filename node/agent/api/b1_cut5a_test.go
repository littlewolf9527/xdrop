package api

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

type cut5ReceiptFunc func() error

func (f cut5ReceiptFunc) Quiesce() error { return f() }

func TestB1Cut5AConditionSelectors(t *testing.T) {
	h := &Handlers{condA: new(ebpf.Map), condB: new(ebpf.Map), cidrCondA: new(ebpf.Map), cidrCondB: new(ebpf.Map)}
	if h.quiescenceConfirmed {
		t.Fatal("zero-value handler must await receipt")
	}
	for _, slot := range []int{0, 1, 0} {
		h.activeRuleSlot.Store(int32(slot))
		active, shadow, cidrActive, cidrShadow := h.condA, h.condB, h.cidrCondA, h.cidrCondB
		if slot == 1 {
			active, shadow, cidrActive, cidrShadow = shadow, active, cidrShadow, cidrActive
		}
		if h.activeCond() != active || h.shadowCond() != shadow || h.activeCidrCond() != cidrActive || h.shadowCidrCond() != cidrShadow {
			t.Fatalf("condition selector pairing slot=%d", slot)
		}
	}
}

func TestB1Cut5AReceiptRetry(t *testing.T) {
	for _, success := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(success), func(t *testing.T) {
			h := &Handlers{}
			calls := 0
			h.quiescer = cut5ReceiptFunc(func() error {
				calls++
				if h.publishMu.TryLock() {
					h.publishMu.Unlock()
					t.Fatal("receipt released publishMu")
				}
				if calls == success {
					return nil
				}
				return errors.New("injected receipt failure")
			})
			h.publishMu.Lock()
			err := h.awaitQuiescence()
			h.publishMu.Unlock()
			want := success
			if want > 3 {
				want = 3
			}
			if calls != want || (err == nil) != (success <= 3) || h.quiescenceConfirmed != (success <= 3) {
				t.Fatalf("receipt attempts=%d success=%v confirmed=%v", calls, err == nil, h.quiescenceConfirmed)
			}
		})
	}
}

func TestB1Cut5ADuplicateLogicalPreflight(t *testing.T) {
	for _, pair := range []string{
		`[{"id":"a","logical_id":7,"src_ip":"192.0.2.1","action":"drop"},{"id":"b","logical_id":7,"src_ip":"192.0.2.2","action":"drop"}]`,
		`[{"id":"a","logical_id":7,"src_cidr":"192.0.2.0/24","action":"drop"},{"id":"b","logical_id":7,"src_cidr":"198.51.100.0/24","action":"drop"}]`,
		`[{"id":"a","logical_id":7,"src_ip":"192.0.2.1","action":"drop"},{"id":"b","logical_id":7,"src_cidr":"198.51.100.0/24","action":"drop"}]`,
		`[{"id":"","logical_id":7},{"id":"","logical_id":7}]`,
	} {
		h := &Handlers{quiescer: cut5ReceiptFunc(func() error { t.Fatal("duplicate logical ID reached receipt"); return nil })}
		r := gin.New()
		r.POST("/sync", h.AtomicSync)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/sync", strings.NewReader(`{"rules":`+pair+`}`)))
		if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"duplicate_logical_id"`) || !strings.Contains(w.Body.String(), `"added":0`) || !strings.Contains(w.Body.String(), `"failed":1`) {
			t.Fatalf("duplicate logical preflight=%d %s", w.Code, w.Body.String())
		}
	}
	if err := checkAtomicLogicalIDs([]Rule{{ID: "a"}, {ID: "b"}}); err != nil {
		t.Fatal("zero logical IDs rejected", err)
	}
}

func TestB1Cut5AIntent(t *testing.T) {
	for _, kind := range []string{"exact", "cidr"} {
		for _, field := range []string{"logical0", "logical3", "length", "anomaly", "ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				old := Rule{Action: "drop", Protocol: "tcp", LogicalID: 3, MatchAnomaly: 1, PktLenMin: 100, PktLenMax: 200, TcpFlags: "SYN, !ACK"}
				if field == "logical0" {
					old.LogicalID = 0
				}
				incoming := old
				incoming.TcpFlags = "!ACK,SYN"
				equal := func(r Rule) bool {
					if kind == "exact" {
						return sameExactContent(ruleToStored(RuleKey{}, old), RuleKey{}, r)
					}
					return sameCIDRContent(ruleToStoredCIDR(CIDRRuleKey{}, "192.0.2.0/24", "", old), "192.0.2.0/24", "", 0, 0, 0, r)
				}
				if !equal(incoming) {
					t.Fatal("canonical flag intent differs")
				}
				value := "64"
				switch field {
				case "logical0", "logical3":
					incoming.LogicalID = 7
				case "length":
					incoming.PktLenMin, incoming.PktLenMax = 300, 400
				case "anomaly":
					incoming.MatchAnomaly = 2
				default:
					var target **string
					switch field {
					case "ttl":
						target = &incoming.TTL
					case "dscp":
						target = &incoming.DSCP
					case "icmp_type":
						target = &incoming.ICMPType
					case "icmp_code":
						target = &incoming.ICMPCode
					case "fragment":
						target = &incoming.Fragment
					case "pkt_len":
						target = &incoming.PktLen
					}
					*target = &value
					if equal(incoming) {
						t.Fatal("absent equals value")
					}
					stable := value
					*target = &stable
					presentValue := incoming
					*target = &value
					value = ""
					if equal(incoming) {
						t.Fatal("absent equals empty")
					}
					old = presentValue // final comparison also guards empty versus value
				}
				if equal(incoming) {
					t.Fatalf("intent ignored %s", field)
				}
			})
		}
	}
}

type cut5LogicalMap map[uint32]bool

func (m cut5LogicalMap) NextKey(cursor, out interface{}) error {
	keys := []int{}
	for k := range m {
		if cursor == nil || k > cursor.(uint32) {
			keys = append(keys, int(k))
		}
	}
	sort.Ints(keys)
	if len(keys) == 0 {
		return ebpf.ErrKeyNotExist
	}
	*out.(*uint32) = uint32(keys[0])
	return nil
}
func (m cut5LogicalMap) Delete(k interface{}) error { delete(m, k.(uint32)); return nil }
func TestB1Cut5AReconcileActualKeys(t *testing.T) {
	for _, name := range []string{"id_rl_states", "id_counts"} {
		t.Run(name, func(t *testing.T) {
			m := cut5LogicalMap{0: true, 3: true, 7: true, 99: true}
			if err := reconcileLogicalKeys(m, map[uint32]bool{3: true, 7: true, 8: true}); err != nil {
				t.Fatal(err)
			}
			if len(m) != 2 || !m[3] || !m[7] {
				t.Fatalf("actual-key reconciliation=%v", m)
			}
		})
	}
}
