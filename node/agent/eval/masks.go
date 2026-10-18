// Package eval is a local test instrument, never a production dependency.
// The decision core receives parsed masks; it does not load BPF or run Python.
package eval

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Mask uint8

const (
	SrcIP Mask = 1 << iota
	DstIP
	SrcPort
	DstPort
	Protocol
)

type Tables struct {
	contract       Contract // set only by explicit, certified LoadTables
	Masks          []Mask
	Valid          uint64
	Order          []int
	WhitelistOrder []int
}

var comments = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

func cleanC(s string) string { return comments.ReplaceAllString(s, "") }

func sourceFile(root, name string) ([]byte, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("source root must be absolute: %q", root)
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(base, name))
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("source escapes root: %s", path)
	}
	return os.ReadFile(path)
}

// LoadTables parses the generated blacklist table and whitelist call sequence
// from an explicit root. Tests first certify the whitelist bodies with S1-5.
// Nothing is derived from the process working directory or comments in C.
func LoadTables(root string, contract Contract) (Tables, error) {
	t := Tables{contract: contract}
	if _, ok := contractHashes[contract]; !ok {
		return t, fmt.Errorf("explicit known combo contract required")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) {
		return t, fmt.Errorf("absolute existing source root required: %q: %v", root, err)
	}
	// Each parsed byte slice is the very same slice authenticated below.
	sources := map[string][]byte{}
	for name := range contractHashes[contract] {
		data, err := sourceFile(base, name)
		if err != nil {
			return t, err
		}
		sources[name] = data
	}
	raw := sources["node/bpf/combo_masks.h"]
	s := cleanC(string(raw))
	symbols := map[string]Mask{}
	defs := regexp.MustCompile(`(?m)^#define\s+(CM_[A-Z_]+)\s+\(1u << ([0-9]+)\)\s*$`).FindAllStringSubmatch(s, -1)
	for _, d := range defs {
		n, _ := strconv.Atoi(d[2])
		if n > 4 || symbols[d[1]] != 0 {
			return t, fmt.Errorf("invalid mask definition %q", d[0])
		}
		symbols[d[1]] = 1 << n
	}
	expected := map[string]Mask{"CM_SRC_IP": SrcIP, "CM_DST_IP": DstIP, "CM_SRC_PORT": SrcPort, "CM_DST_PORT": DstPort, "CM_PROTOCOL": Protocol}
	if len(regexp.MustCompile(`(?m)^#define\s+CM_`).FindAllString(s, -1)) != len(defs) {
		return t, fmt.Errorf("unknown mask definition syntax")
	}
	if len(symbols) != len(expected) {
		return t, fmt.Errorf("mask definitions=%d, want 5", len(symbols))
	}
	for k, v := range expected {
		if symbols[k] != v {
			return t, fmt.Errorf("mask definition %s differs", k)
		}
	}
	bm := regexp.MustCompile(`(?m)^#define\s+COMBO_VALID_BITMAP\s+(0x[0-9A-Fa-f]+)ULL\s*$`).FindAllStringSubmatch(s, -1)
	if len(bm) != 1 {
		return t, fmt.Errorf("valid bitmap definitions=%d, want 1", len(bm))
	}
	t.Valid, err = strconv.ParseUint(bm[0][1][2:], 16, 64)
	if err != nil {
		return t, err
	}
	body := regexp.MustCompile(`(?s)static\s+const\s+__u8\s+combo_field_mask\[(?:|COMBO_TABLE_SLOTS)\]\s*=\s*\{(.*?)\}\s*;`).FindAllStringSubmatch(s, -1)
	if len(body) != 1 {
		return t, fmt.Errorf("mask tables=%d, want 1", len(body))
	}
	entries := strings.Split(body[0][1], ",")
	if strings.TrimSpace(entries[len(entries)-1]) != "" {
		return t, fmt.Errorf("unknown table tail")
	}
	entryRE := regexp.MustCompile(`(?s)^\s*\[([0-9]+)\]\s*=\s*(.*?)\s*$`)
	for _, entry := range entries[:len(entries)-1] {
		m := entryRE.FindStringSubmatch(entry)
		if m == nil {
			return t, fmt.Errorf("unknown table entry %q", entry)
		}
		index, _ := strconv.Atoi(m[1])
		if index != len(t.Masks) {
			return t, fmt.Errorf("table index=%d, want %d", index, len(t.Masks))
		}
		var mask Mask
		if m[2] != "0" {
			for _, token := range strings.Split(m[2], "|") {
				token = strings.TrimSpace(token)
				v, ok := symbols[token]
				if !ok || mask&v != 0 {
					return t, fmt.Errorf("unknown/duplicate mask token %q", token)
				}
				mask |= v
			}
		}
		t.Masks = append(t.Masks, mask)
		if t.Valid&(1<<index) != 0 {
			t.Order = append(t.Order, index)
		}
	}
	if contract == S2b || contract == B1 {
		orders := regexp.MustCompile(`(?s)static\s+const\s+__u8\s+combo_order\[\]\s*=\s*\{([^{}]*)\}\s*;`).FindAllStringSubmatch(s, -1)
		if len(orders) != 1 || len(regexp.MustCompile(`\bcombo_order\s*\[\s*\]\s*=`).FindAllString(s, -1)) != 1 {
			return t, fmt.Errorf("s2b order definitions must be exactly one")
		}
		lengths := regexp.MustCompile(`(?m)^#define\s+COMBO_ORDER_LEN\s+([^\n]+)$`).FindAllStringSubmatch(s, -1)
		if len(lengths) != 1 || strings.TrimSpace(lengths[0][1]) != "(sizeof(combo_order) / sizeof(combo_order[0]))" {
			return t, fmt.Errorf("s2b order length must use actual sizeof")
		}
		t.Order = nil
		values := strings.Split(orders[0][1], ",")
		if strings.TrimSpace(values[len(values)-1]) != "" {
			return t, fmt.Errorf("s2b order tail")
		}
		for _, value := range values[:len(values)-1] {
			value = strings.TrimSpace(value)
			if !regexp.MustCompile(`^-?[0-9]+$`).MatchString(value) {
				return t, fmt.Errorf("unknown s2b order syntax %q", value)
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return t, fmt.Errorf("s2b order range: %w", err)
			}
			t.Order = append(t.Order, n)
		}
	}
	hdr := sources["node/bpf/xdrop.h"]
	h := strings.ReplaceAll(cleanC(string(hdr)), "\\\n", " ")
	roster := map[string]int{}
	for _, d := range regexp.MustCompile(`(?m)^#define\s+(COMBO_[A-Z0-9_]+)\s+(\d+)\s*$`).FindAllStringSubmatch(h, -1) {
		if _, ok := roster[d[1]]; ok {
			return t, fmt.Errorf("duplicate combo symbol %s", d[1])
		}
		roster[d[1]], _ = strconv.Atoi(d[2])
	}
	if roster["COMBO_MAX"] != 34 || len(roster) != bits.OnesCount64(contract.bitmap())+1 {
		return t, fmt.Errorf("invalid COMBO roster")
	}
	for name, n := range historicalRoster {
		got, ok := roster[name]
		if contract.active(n) {
			if !ok || got != n {
				return t, fmt.Errorf("combo roster mapping differs: %s", name)
			}
		} else if ok {
			return t, fmt.Errorf("retired combo in active roster: %s", name)
		}
	}
	gate := sources["node/bpf/xdrop_gate.c"]
	g := strings.ReplaceAll(cleanC(string(gate)), "\\\n", " ")
	g = regexp.MustCompile(`(?m)^[\t ]*#[^\n]*`).ReplaceAllString(g, "")
	calls := regexp.MustCompile(`(?s)\bWL_COMBO_CHECK\s*\(\s*(COMBO_[A-Z0-9_]+)\s*,\s*\{[^{}]*\}\s*\)`)
	for _, m := range calls.FindAllStringSubmatch(g, -1) {
		n, ok := roster[m[1]]
		if !ok {
			return t, fmt.Errorf("unknown whitelist combo %s", m[1])
		}
		t.WhitelistOrder = append(t.WhitelistOrder, n)
	}
	if strings.Contains(calls.ReplaceAllString(g, ""), "WL_COMBO_CHECK") {
		return t, fmt.Errorf("unparsed whitelist invocation")
	}
	if err := t.Validate(); err != nil {
		return t, err
	}
	for name, want := range contractHashes[contract] {
		b := sources[name]
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			return t, fmt.Errorf("%s input identity mismatch: %s", contract, name)
		}
	}
	return t, nil
}

// validateStructure rejects malformed tables independently of their version.
// Validate always invokes it AND the selected strict contract.
func (t Tables) validateStructure() error {
	if len(t.Masks) == 0 || len(t.Masks) > 64 {
		return fmt.Errorf("table length outside bitmap range")
	}
	if len(t.Masks) < 64 && t.Valid>>len(t.Masks) != 0 {
		return fmt.Errorf("bitmap outside table")
	}
	for i, m := range t.Masks {
		if m > 31 || (m != 0) != (t.Valid&(1<<i) != 0) {
			return fmt.Errorf("mask/bitmap disagreement at %d", i)
		}
	}
	for _, seq := range [][]int{t.Order, t.WhitelistOrder} {
		seen := uint64(0)
		for _, n := range seq {
			if n < 0 || n >= len(t.Masks) || t.Valid&(1<<n) == 0 || seen&(1<<n) != 0 {
				return fmt.Errorf("out of range/absent/duplicate order entry %d", n)
			}
			seen |= 1 << n
		}
	}
	if len(t.Order) != bits.OnesCount64(t.Valid) {
		return fmt.Errorf("order missing valid entries")
	}
	return nil
}

func (t Tables) Validate() error {
	if err := t.validateStructure(); err != nil {
		return err
	}
	if _, ok := contractHashes[t.contract]; !ok {
		return fmt.Errorf("explicit known combo contract required")
	}
	if len(t.Masks) != 34 {
		return fmt.Errorf("table length=%d, want 34", len(t.Masks))
	}
	wantBits := bits.OnesCount64(t.contract.bitmap())
	if bits.OnesCount64(t.Valid) != wantBits {
		return fmt.Errorf("bitmap population=%d, want %d for %s", bits.OnesCount64(t.Valid), wantBits, t.contract)
	}
	if t.Valid != t.contract.bitmap() {
		return fmt.Errorf("bitmap differs from %s exact holes", t.contract)
	}
	if len(t.Order) != wantBits || len(t.WhitelistOrder) != 31 {
		return fmt.Errorf("order lengths=%d/%d, want %d/31", len(t.Order), len(t.WhitelistOrder), wantBits)
	}
	b, w := 0, 0
	for i, m := range t.Masks {
		if m != t.contract.mask(i) {
			return fmt.Errorf("%s fixed mask differs at %d: %d != %d", t.contract, i, m, t.contract.mask(i))
		}
		if !t.contract.active(i) {
			continue
		}
		if t.contract != S2b && t.contract != B1 && t.Order[b] != i {
			return fmt.Errorf("blacklist order at %d differs", b)
		}
		b++
		if i != 20 && i != 32 {
			if t.WhitelistOrder[w] != i {
				return fmt.Errorf("whitelist order at %d differs", w)
			}
			w++
		}
	}
	if t.contract == S2b || t.contract == B1 {
		want := make([]int, 0, 31)
		for n := 0; n < 34; n++ {
			if S2b.active(n) {
				want = append(want, n)
			}
		}
		sort.Slice(want, func(a, b int) bool {
			wa, wb := bits.OnesCount8(uint8(S2b.mask(want[a]))), bits.OnesCount8(uint8(S2b.mask(want[b])))
			if wa != wb {
				return wa > wb
			}
			return want[a] < want[b]
		})
		for i, n := range want {
			if t.Order[i] != n {
				return fmt.Errorf("s2b K order at %d: %d != %d", i, t.Order[i], n)
			}
		}
	}
	return nil
}
