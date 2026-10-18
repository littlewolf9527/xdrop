package cidr

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
)

func TestTD075FindNestedTable(t *testing.T) {
	parent := PrefixIndex{"10.0.0.0/16", 7}
	child := PrefixIndex{"10.0.1.0/24", 2}
	for _, tc := range []struct {
		name     string
		in       []PrefixIndex
		want     [2]PrefixIndex
		conflict bool
	}{
		{"empty", nil, [2]PrefixIndex{}, false},
		{"single", []PrefixIndex{parent}, [2]PrefixIndex{}, false},
		{"v4_forward", []PrefixIndex{parent, child}, [2]PrefixIndex{parent, child}, true},
		{"v4_reverse", []PrefixIndex{child, parent}, [2]PrefixIndex{parent, child}, true},
		{"siblings", []PrefixIndex{{"10.0.0.0/24", 0}, {"10.0.1.0/24", 1}}, [2]PrefixIndex{}, false},
		{"families", []PrefixIndex{{"0.0.0.0/0", 0}, {"::/0", 1}}, [2]PrefixIndex{}, false},
		{"v6", []PrefixIndex{{"2001:db8:1::/48", 3}, {"2001:db8::/32", 8}}, [2]PrefixIndex{{"2001:db8::/32", 8}, {"2001:db8:1::/48", 3}}, true},
		{"v4_zero", []PrefixIndex{child, {"0.0.0.0/0", 9}}, [2]PrefixIndex{{"0.0.0.0/0", 9}, child}, true},
		{"v6_zero", []PrefixIndex{{"2001:db8::1/128", 3}, {"::/0", 4}}, [2]PrefixIndex{{"::/0", 4}, {"2001:db8::1/128", 3}}, true},
		{"v4_host", []PrefixIndex{{"192.0.2.1/32", 4}, {"192.0.2.0/31", 5}}, [2]PrefixIndex{{"192.0.2.0/31", 5}, {"192.0.2.1/32", 4}}, true},
		{"same_network_sort", []PrefixIndex{{"10.0.0.0/24", 1}, parent}, [2]PrefixIndex{parent, {"10.0.0.0/24", 1}}, true},
		{"first_adjacent_pair", []PrefixIndex{{"10.2.0.0/16", 0}, {"10.2.1.0/24", 1}, child, parent, {"10.0.1.128/25", 5}}, [2]PrefixIndex{parent, child}, true},
		{"family_order", []PrefixIndex{{"::/0", 0}, {"2001:db8::/32", 1}, child, parent}, [2]PrefixIndex{parent, child}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]PrefixIndex(nil), tc.in...)
			a, b, found := FindNested(tc.in)
			if found != tc.conflict || [2]PrefixIndex{a, b} != tc.want {
				t.Fatalf("first adjacent container/index pair=%v found=%v want=%v/%v", [2]PrefixIndex{a, b}, found, tc.want, tc.conflict)
			}
			if !reflect.DeepEqual(before, tc.in) {
				t.Fatal("input order mutated")
			}
		})
	}
}

func TestTD075FindNestedMappedDeterminism(t *testing.T) {
	in := []PrefixIndex{{"::ffff:192.0.2.0/120", 3}, {"::ffff:192.0.2.1/128", 1}, {"192.0.2.0/24", 2}}
	a, b, found := FindNested(in)
	for i := 0; i < 20; i++ {
		in[0], in[2] = in[2], in[0]
		x, y, got := FindNested(in)
		if x != a || y != b || got != found {
			t.Fatal("mapped input result is not deterministic")
		}
	}
}

func TestTD075FindNestedDifferential(t *testing.T) {
	var rounds, mismatches, conflictRounds int
	check := func(entries []PrefixIndex) {
		rounds++
		_, _, got := FindNested(entries)
		want := false
		for i := 0; i < len(entries); i++ {
			for j := i + 1; j < len(entries); j++ {
				conflict, err := CheckOverlap(entries[i].Prefix, []string{entries[j].Prefix})
				if err != nil {
					t.Fatal(err)
				}
				if conflict != "" {
					want = true
				}
			}
		}
		if want {
			conflictRounds++
		}
		if got != want {
			mismatches++
			t.Errorf("round=%d got=%v want=%v entries=%v", rounds, got, want, entries)
		}
	}
	// Full prefix-length ranges and a small mixed-family address pool. No pair
	// is injected into random rounds; the two fixed rounds below count as rounds.
	pools := [][]string{{"10.0.0.1", "10.0.1.1", "172.16.0.1", "192.168.1.1"}, {"2001:db8::1", "2001:db8:1::1", "2001:db8:2::1", "2001:db8:ffff::1"}}
	for _, seed := range []int64{75, 1075, 2075, 3075} {
		rng := rand.New(rand.NewSource(seed))
		for round := 0; round < 250; round++ {
			entries := []PrefixIndex{}
			seen := map[string]bool{}
			for i, n := 0, 1+rng.Intn(12); i < n; i++ {
				family := rng.Intn(2)
				bits := 32
				if family == 1 {
					bits = 128
				}
				ip := net.ParseIP(pools[family][rng.Intn(len(pools[family]))])
				if family == 0 {
					ip = ip.To4()
				}
				mask := net.CIDRMask(rng.Intn(bits+1), bits)
				network := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
				prefix := network.String()
				if !seen[prefix] {
					seen[prefix] = true
					entries = append(entries, PrefixIndex{prefix, i})
				}
			}
			check(entries)
		}
	}
	check([]PrefixIndex{{"10.0.0.0/16", 0}, {"10.0.1.0/24", 1}})
	check([]PrefixIndex{{"192.0.2.0/24", 0}, {"198.51.100.0/24", 1}, {"2001:db8::/32", 2}})
	fmt.Printf("TD075_DIFF rounds=%d mismatch=%d conflict_rounds=%d\n", rounds, mismatches, conflictRounds)
	if rounds < 1000 || mismatches != 0 || conflictRounds <= 0 || conflictRounds >= rounds {
		t.Fatal("differential coverage/count gate failed")
	}
}

func TestTD075FindNestedScale(t *testing.T) {
	const count = 200000
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v6=%v", v6), func(t *testing.T) {
			entries := make([]PrefixIndex, count)
			for i := range entries {
				var network *net.IPNet
				if v6 {
					ip := net.ParseIP("2001:db8:1::").To16()
					binary.BigEndian.PutUint32(ip[12:], uint32(i))
					network = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				} else {
					ip := make(net.IP, 4)
					binary.BigEndian.PutUint32(ip, uint32(0x0a400000+i))
					network = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				}
				entries[i] = PrefixIndex{network.String(), i}
			}
			t.Run("disjoint", func(t *testing.T) {
				if a, b, found := FindNested(entries); found {
					t.Fatalf("200000 disjoint prefixes reported conflict: %v %v", a, b)
				}
			})
			pairs := [][2]string{{"10.0.0.0/31", "10.0.0.1/32"}, {"10.255.255.254/31", "10.255.255.255/32"}}
			if v6 {
				pairs = [][2]string{{"2001:db8::/127", "2001:db8::1/128"}, {"2001:db8:ffff::/127", "2001:db8:ffff::1/128"}}
			}
			for where, pair := range pairs {
				t.Run([]string{"first", "last"}[where], func(t *testing.T) {
					want := [2]PrefixIndex{{pair[0], count}, {pair[1], count + 1}}
					input := append(append([]PrefixIndex(nil), entries...), want[1], want[0])
					a, b, found := FindNested(input)
					if !found || [2]PrefixIndex{a, b} != want {
						t.Fatalf("scale boundary pair=%v/%v found=%v want=%v", a, b, found, want)
					}
				})
			}
		})
	}
}
