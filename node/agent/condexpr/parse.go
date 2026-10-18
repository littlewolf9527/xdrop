// 权威在 shared/condexpr/，controller 与 node 各有一份逐字节拷贝，⛔ 手改拷贝。
package condexpr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var fragmentAtoms = []struct {
	name   string
	values []int
}{
	{"nofrag", []int{0, 4}}, {"first", []int{2, 6}},
	{"middle", []int{3, 7}}, {"last", []int{1, 5}},
}

func decimal(s string, max int) (int, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("invalid decimal %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid decimal %q", s)
		}
	}
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil || n > uint64(max) {
		return 0, fmt.Errorf("value %q outside 0-%d", s, max)
	}
	return int(n), nil
}

func merge(spans []Span) []Span {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Lo != spans[j].Lo {
			return spans[i].Lo < spans[j].Lo
		}
		return spans[i].Hi < spans[j].Hi
	})
	out := make([]Span, 0, len(spans))
	for _, s := range spans {
		if len(out) > 0 && int(s.Lo) <= int(out[len(out)-1].Hi)+1 {
			if s.Hi > out[len(out)-1].Hi {
				out[len(out)-1].Hi = s.Hi
			}
		} else {
			out = append(out, s)
		}
	}
	return out
}

func format(spans []Span) string {
	parts := make([]string, len(spans))
	for i, s := range spans {
		parts[i] = strconv.Itoa(int(s.Lo))
		if s.Lo != s.Hi {
			parts[i] += "-" + strconv.Itoa(int(s.Hi))
		}
	}
	return strings.Join(parts, ",")
}

func contains(spans []Span, n int) bool {
	for _, s := range spans {
		if n >= int(s.Lo) && n <= int(s.Hi) {
			return true
		}
	}
	return false
}

// Parse implements the six expression fields; legacy flags use ParseTCPFlags.
func Parse(key, raw string) (string, []Span, error) {
	var a Attribute
	found := false
	for _, entry := range ExpressionAttributes() {
		if entry.Key == key {
			a = entry
			found = true
			break
		}
	}
	if !found {
		return "", nil, fmt.Errorf("unknown expression key %q", key)
	}
	// Only ASCII space and tab are lexical whitespace, including at the edges.
	for _, c := range raw {
		if c == '\n' || c == '\r' || c > 127 {
			return "", nil, fmt.Errorf("%s: illegal character", key)
		}
	}
	s := strings.Trim(raw, " \t")
	neg := strings.HasPrefix(s, "!")
	if neg {
		s = strings.Trim(s[1:], " \t")
	}
	if s == "" {
		return "", nil, fmt.Errorf("%s: empty expression", key)
	}
	var spans []Span
	for _, part := range strings.Split(s, ",") {
		part = strings.Trim(part, " \t")
		if part == "" {
			return "", nil, fmt.Errorf("%s: empty item", key)
		}
		if a.Kind == FragmentNames {
			name := strings.ToLower(part)
			matched := false
			for _, atom := range fragmentAtoms {
				if name == atom.name || name == "frag" && atom.name != "nofrag" || name == "nonfirst" && (atom.name == "middle" || atom.name == "last") {
					matched = true
					for _, v := range atom.values {
						spans = append(spans, Span{uint16(v), uint16(v)})
					}
				}
			}
			if !matched {
				return "", nil, fmt.Errorf("fragment: invalid name %q", part)
			}
			continue
		}
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return "", nil, fmt.Errorf("%s: invalid interval %q", key, part)
		}
		lo, e := decimal(strings.Trim(ends[0], " \t"), a.Max)
		if e != nil {
			return "", nil, fmt.Errorf("%s: %w", key, e)
		}
		hi := lo
		if len(ends) == 2 {
			hi, e = decimal(strings.Trim(ends[1], " \t"), a.Max)
			if e != nil {
				return "", nil, fmt.Errorf("%s: %w", key, e)
			}
		}
		if lo > hi {
			return "", nil, fmt.Errorf("%s: reversed interval", key)
		}
		spans = append(spans, Span{uint16(lo), uint16(hi)})
	}
	spans = merge(spans)
	if neg {
		var complement []Span
		next := 0
		for _, s := range spans {
			if next < int(s.Lo) {
				complement = append(complement, Span{uint16(next), s.Lo - 1})
			}
			next = int(s.Hi) + 1
		}
		if next <= a.Max {
			complement = append(complement, Span{uint16(next), uint16(a.Max)})
		}
		spans = complement
	}
	if len(spans) == 0 {
		return "", nil, fmt.Errorf("%s: empty set", key)
	}
	if len(spans) == 1 && spans[0] == (Span{0, uint16(a.Max)}) {
		return "", nil, fmt.Errorf("%s: full set; please remove this key", key)
	}
	canonical := format(spans)
	if a.Kind == FragmentNames {
		var names []string
		for _, atom := range fragmentAtoms {
			if contains(spans, atom.values[0]) {
				names = append(names, atom.name)
			}
		}
		canonical = strings.Join(names, ",")
	}
	return canonical, spans, nil
}

// ParseTCPFlags preserves the existing two implementations' grammar, including
// ignored empty comma segments, Unicode TrimSpace, and signed contradictions.
func ParseTCPFlags(s string) (mask, value uint8, canonical string, err error) {
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		neg := strings.HasPrefix(part, "!")
		if neg {
			part = part[1:]
		}
		bit := uint8(0)
		for i, n := range names {
			if n == part {
				bit = 1 << i
			}
		}
		if bit == 0 {
			return 0, 0, "", fmt.Errorf("unknown TCP flag %q", part)
		}
		if mask&bit != 0 && (value&bit != 0) == neg {
			return 0, 0, "", fmt.Errorf("contradictory TCP flags: %s", part)
		}
		mask |= bit
		if !neg {
			value |= bit
		}
	}
	var parts []string
	for i := len(names) - 1; i >= 0; i-- {
		bit := uint8(1 << i)
		if mask&bit == 0 {
			continue
		}
		n := names[i]
		if value&bit == 0 {
			n = "!" + n
		}
		parts = append(parts, n)
	}
	return mask, value, strings.Join(parts, ","), nil
}
