// 权威在 shared/condexpr/，controller 与 node 各有一份逐字节拷贝，⛔ 手改拷贝。
package condexpr

// The H ABI uses four physical candidates and two length spans per candidate.
const MaxCandidates = 4
const SpansPerCandidate = 2

type Kind uint8

const (
	Set8 Kind = iota
	Interval16
	FragmentNames
)

type Attribute struct {
	Key        string
	Kind       Kind
	Max        int
	Table      int    // -1: separate fragment vector; -2: length spans
	Protocols  string // "*" or comma-separated protocol names
	Family     string // "any" or "ipv4-anchor"
	Expression bool
	LegacyKey  string
}

// Registry returns a copy: callers cannot mutate the compiler's registry.
func Registry() []Attribute {
	return []Attribute{
		{"ttl", Set8, 255, 0, "*", "any", true, ""},
		{"dscp", Set8, 63, 1, "*", "any", true, ""},
		{"tcp_flags", Set8, 255, 2, "tcp", "any", false, "tcp_flags"},
		{"icmp_type", Set8, 255, 3, "icmp,icmpv6", "any", true, ""},
		{"icmp_code", Set8, 255, 4, "icmp,icmpv6", "any", true, ""},
		{"anomaly", Set8, 15, 5, "*", "any", false, "match_anomaly"},
		{"fragment", FragmentNames, 7, -1, "*", "ipv4-anchor", true, ""},
		{"pkt_len", Interval16, 65535, -2, "*", "any", true, "pkt_len_min,max"},
	}
}

func ExpressionAttributes() []Attribute {
	var out []Attribute
	for _, a := range Registry() {
		if a.Expression {
			out = append(out, a)
		}
	}
	return out
}

type Span struct{ Lo, Hi uint16 }

// Fields deliberately carries only the six nullable expression strings.
type Fields struct{ TTL, DSCP, ICMPType, ICMPCode, Fragment, PktLen *string }

func (f Fields) Values() [8]*string {
	return [8]*string{f.TTL, f.DSCP, nil, f.ICMPType, f.ICMPCode, nil, f.Fragment, f.PktLen}
}

func fieldsFrom(v [8]string, presence [8]*string) Fields {
	p := func(i int) *string {
		if presence[i] == nil {
			return nil
		}
		s := v[i]
		return &s
	}
	return Fields{p(0), p(1), p(3), p(4), p(6), p(7)}
}
