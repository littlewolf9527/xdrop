package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

func cut4BString(s string) *string { return &s }
func cut4BRule() Rule              { return Rule{ID: "r", LogicalID: 17, Protocol: "tcp", Action: "drop"} }
func TestB1ConditionCanonicalBytes(t *testing.T) {
	r := cut4BRule()
	r.RateLimit = 999
	row, e := EncodeConditionValue([]Rule{r})
	if e != nil {
		t.Fatal(e)
	}
	if row.Active != 1 || row.ICMPReq != 0 || row.TCPReq != 0 || row.Pad != ([1]byte{}) {
		t.Fatalf("header=%+v", row)
	}
	maxima := []int{255, 63, 255, 255, 255, 15}
	for table, max := range maxima {
		for v := 0; v < 256; v++ {
			got := (row.Tab[table][v/2] >> uint(4*(v%2))) & 15
			want := byte(0)
			if v <= max {
				want = 1
			}
			if got != want {
				t.Fatalf("table=%d value=%d bits=%x want=%x", table, v, got, want)
			}
		}
	}
	for v := 0; v < 8; v++ {
		if (row.Frag[v/2]>>uint(4*(v%2)))&15 != 1 {
			t.Fatalf("unconstrained fragment %d", v)
		}
	}
	if row.Len[0] != ([2]ConditionSpan{{0, 65535}, {1, 0}}) {
		t.Fatalf("unconstrained lengths=%v", row.Len[0])
	}
	if row.Action[0] != ActionDrop || row.Rate[0] != 0 || row.RuleID[0] != 17 {
		t.Fatalf("candidate output=%+v", row)
	}
	for k := 1; k < 4; k++ {
		if row.Len[k] != ([2]ConditionSpan{}) || row.Action[k] != 0 || row.Rate[k] != 0 || row.RuleID[k] != 0 {
			t.Fatalf("inactive candidate=%d", k)
		}
	}
	r.PktLen = cut4BString("100-200")
	row, e = EncodeConditionValue([]Rule{r})
	if e != nil || row.Len[0] != ([2]ConditionSpan{{100, 200}, {1, 0}}) {
		t.Fatalf("one length=%v %v", row.Len[0], e)
	}
	for _, field := range []string{"type", "code"} {
		r = cut4BRule()
		r.Protocol = "icmp"
		if field == "type" {
			r.ICMPType = cut4BString("8")
		} else {
			r.ICMPCode = cut4BString("0")
		}
		row, e = EncodeConditionValue([]Rule{r})
		if e != nil || row.ICMPReq != 1 {
			t.Fatalf("icmp_req %s=%d %v", field, row.ICMPReq, e)
		}
	}
	r = cut4BRule()
	r.Action = "rate_limit"
	r.RateLimit = 1000
	row, e = EncodeConditionValue([]Rule{r})
	if e != nil || row.Action[0] != 2 || row.Rate[0] != 1000 {
		t.Fatalf("rate output=%+v %v", row, e)
	}
	var wire bytes.Buffer
	if e := binary.Write(&wire, binary.LittleEndian, row); e != nil {
		t.Fatal(e)
	}
	if wire.Len() != 844 || binary.LittleEndian.Uint32(wire.Bytes()[808:]) != 1000 || binary.LittleEndian.Uint32(wire.Bytes()[824:]) != 17 {
		t.Fatalf("wire ABI len=%d", wire.Len())
	}
}

func TestB1ConditionEncodingRejects(t *testing.T) {
	for _, c := range []string{"zero-id", "pass", "unknown-action", "zero-rate", "noncanonical", "empty", "new-old", "different-tuples", "duplicate-logical-id", "empty-row"} {
		t.Run(c, func(t *testing.T) {
			r := cut4BRule()
			rules := []Rule{r}
			switch c {
			case "zero-id":
				rules[0].LogicalID = 0
			case "pass":
				rules[0].Action = "pass"
			case "unknown-action":
				rules[0].Action = "DROP"
			case "zero-rate":
				rules[0].Action = "rate_limit"
			case "noncanonical":
				rules[0].TTL = cut4BString("128,64")
			case "empty":
				rules[0].TTL = cut4BString("")
			case "new-old":
				rules[0].PktLen = cut4BString("100")
				rules[0].PktLenMin = 100
			case "different-tuples":
				r.ID = "other"
				r.LogicalID = 18
				r.Protocol = "udp"
				rules = append(rules, r)
			case "duplicate-logical-id":
				r.ID = "other"
				rules = append(rules, r)
			case "empty-row":
				rules = nil
			}
			row, e := EncodeConditionValue(rules)
			if e == nil || row != (ConditionValue{}) {
				t.Fatalf("accepted or partial row: %v", e)
			}
		})
	}
}

func TestB1ConditionABILimits(t *testing.T) {
	b, e := os.ReadFile("../../bpf/xdrop.h")
	if e != nil {
		t.Fatal(e)
	}
	m := regexp.MustCompile(`struct cond_span len\[(\d+)\]\[(\d+)\]`).FindStringSubmatch(string(b))
	if len(m) != 3 || m[1] != fmt.Sprint(condexpr.MaxCandidates) || m[2] != fmt.Sprint(condexpr.SpansPerCandidate) {
		t.Fatalf("C/Go limits=%v %d/%d", m, condexpr.MaxCandidates, condexpr.SpansPerCandidate)
	}
	v := reflect.TypeOf(ConditionValue{})
	offsets := []uintptr{0, 768, 772, 804, 808, 824, 840, 841, 842, 843}
	for i, w := range offsets {
		if v.Field(i).Offset != w {
			t.Fatalf("offset %s=%d want=%d", v.Field(i).Name, v.Field(i).Offset, w)
		}
	}
	if unsafe.Sizeof(ConditionValue{}) != 844 {
		t.Fatal("row size")
	}
}

func TestB1ConditionLegacyFlagsParity(t *testing.T) {
	for _, s := range []string{"", " ", "SYN", "syn,!ack", "SYN,SYN", ",SYN,,", "!SYN,SYN", "SYN,!SYN", "! ACK", "ACK,!FIN", "CWR,ECE,URG,ACK,PSH,RST,SYN,FIN", "wat", "0x02", "\nSYN\t"} {
		a, b, e := parseTcpFlags(s)
		x, y, canonical, ce := condexpr.ParseTCPFlags(s)
		if (e == nil) != (ce == nil) || e == nil && (a != x || b != y || tcpFlagsToString(a, b) != canonical) {
			t.Fatalf("%q node=%d/%d/%v shared=%d/%d/%s/%v", s, a, b, e, x, y, canonical, ce)
		}
	}
	if !strings.Contains(string(ruleValueToBytes(RuleValue{Pad2: [4]byte{1}})[28:]), "\x01") {
		t.Fatal("production serializer must enable conditions")
	}
}
