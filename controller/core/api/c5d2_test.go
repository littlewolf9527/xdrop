package api

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5dPage struct {
	Items  []RuleDTO      `json:"items"`
	Next   *int64         `json:"next_after"`
	Counts map[string]int `json:"counts"`
}

func c5dGet(t *testing.T, f *fixture, query string) c5dPage {
	t.Helper()
	return decoded[c5dPage](t, request(t, f.e, "GET", "/api/v1/rules?"+query, "machine:a", "", 200))
}
func c5dAdd(t *testing.T, f *fixture, in map[string]any) RuleDTO {
	t.Helper()
	b, err := json.Marshal(in)
	require(t, err == nil, err)
	r := decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", "ui", string(b), 201)).RuleDTO
	got := decoded[RuleDTO](t, request(t, f.e, "GET", "/api/v1/rules/"+r.ID, "ui", "", 200))
	require(t, reflect.DeepEqual(got, r), "readback", r.ID)
	if enabled, ok := in["enabled"]; ok {
		require(t, got.Enabled == enabled, "enabled readback", r.ID)
	}
	return r
}
func c5d2Fixture(t *testing.T, f *fixture, v6 bool) ([]RuleDTO, string, string) {
	t.Helper()
	values := []string{"192.0.2.7", "192.0.2.7", "192.0.2.0/24", "192.0.0.0/16", "192.0.2.7/32", "192.0.2.8", "198.51.100.0/24", "2001:db8:ffff::1", "192.0.2.0/25"}
	if v6 {
		values = []string{"2001:db8::7", "2001:db8::7", "2001:db8::/64", "2001:db8::/32", "2001:db8::7/128", "2001:db8::8", "fd00::/64", "203.0.113.1", "2001:db8::/96"}
	}
	fields := []string{"src_ip", "dst_ip", "src_cidr", "dst_cidr", "src_cidr", "dst_ip", "src_cidr", "dst_ip", "dst_cidr"}
	rows := []RuleDTO{}
	for i, raw := range values {
		in := map[string]any{fields[i]: raw, "enabled": !strings.Contains(raw, "/"), "src_port": i + 1, "protocol": "tcp"}
		if i == 1 {
			in["action"], in["rate_limit"] = "rate_limit", 100
		}
		rows = append(rows, c5dAdd(t, f, in))
	}
	t.Logf("readback=%d enabled=4 disabled=5 covering=2 host_prefix=1 inner_prefix=1 other_family=1 v6=%v", len(rows), v6)
	return rows, values[0], values[2]
}
func c5dIDs(rows []RuleDTO) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}

func TestC5D2Query(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		v6 := v6
		t.Run(fmt.Sprintf("family-%v", v6), func(t *testing.T) {
			f := fresh(t)
			rows, ip, prefix := c5d2Fixture(t, f, v6)
			for _, mode := range []string{"IP", "prefix"} {
				mode := mode
				t.Run(mode, func(t *testing.T) {
					q, want := ip, map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 8: true}
					if mode == "prefix" {
						q, want = prefix, map[int]bool{0: true, 1: true, 2: true, 4: true, 5: true, 8: true}
					}
					page := c5dGet(t, f, "counts=1&q="+url.QueryEscape(q))
					for i, name := range []string{"src-IP", "dst-IP", "equal-prefix", "covering-prefix", "host-prefix", "neighbor-IP", "outside-prefix", "other-family", "inner-prefix"} {
						i := i
						name := name
						t.Run(name, func(t *testing.T) {
							require(t, strings.Contains(strings.Join(c5dIDs(page.Items), ","), rows[i].ID) == want[i], "membership", name, page)
						})
					}
					require(t, len(page.Items) == len(want) && page.Counts["all"] == len(want), "exact set", page)
				})
			}
			t.Run("rule-ID", func(t *testing.T) {
				page := c5dGet(t, f, "counts=1&q="+rows[0].ID)
				require(t, reflect.DeepEqual(c5dIDs(page.Items), []string{rows[0].ID}) && page.Counts["all"] == 1, page)
			})
			t.Run("missing-ID", func(t *testing.T) {
				page := c5dGet(t, f, "counts=1&q=rule_00000000000000000000000000000000")
				require(t, len(page.Items) == 0 && reflect.DeepEqual(page.Counts, map[string]int{"all": 0, "drop": 0, "rate_limit": 0, "disabled": 0}), page)
			})
		})
	}
	for _, family := range []struct{ name, ip, zero, prefix string }{
		{"v4", "192.0.2.1", "0.0.0.0/0", "192.0.2.0/24"},
		{"v6", "2001:db8::1", "::/0", "2001:db8::/64"},
	} {
		family := family
		t.Run("IP-stored-zero-prefix/"+family.name, func(t *testing.T) {
			f := fresh(t)
			r := c5dAdd(t, f, map[string]any{"src_cidr": family.zero})
			require(t, r.SrcCIDR == family.zero && r.Kind == "cidr", "stored zero prefix", r)
			p := c5dGet(t, f, "counts=1&q="+url.QueryEscape(family.ip))
			require(t, reflect.DeepEqual(c5dIDs(p.Items), []string{r.ID}) && p.Counts["all"] == 1, "IP covers stored /0", p)
			t.Logf("readback=1 stored_prefix=%s q=%s exact_ids=%v counts.all=%d", r.SrcCIDR, family.ip, c5dIDs(p.Items), p.Counts["all"])
		})
		t.Run("prefix-pages/"+family.name, func(t *testing.T) {
			f := fresh(t)
			want := []int64{}
			for i := 1; i <= 15; i++ {
				r := c5dAdd(t, f, map[string]any{"dst_ip": family.ip, "protocol": "tcp", "dst_port": i})
				require(t, r.LogicalID == int64(i) && r.DstIP == family.ip, "contiguous readback", r)
				want = append(want, r.LogicalID)
			}
			t.Logf("readback=15 q=%s stored_logical_ids=%v", family.prefix, want)
			after, offset := int64(0), 0
			for page, size := range []int{7, 7, 1} {
				p := c5dGet(t, f, fmt.Sprintf("q=%s&limit=7&after=%d", url.QueryEscape(family.prefix), after))
				got := []int64{}
				for _, r := range p.Items {
					got = append(got, r.LogicalID)
				}
				require(t, len(p.Items) == size && reflect.DeepEqual(got, want[offset:offset+size]), "ordered prefix page", page, got, want[offset:offset+size])
				if page < 2 {
					require(t, p.Next != nil && *p.Next == want[offset+size-1], "prefix next cursor", page, p.Next)
					after = *p.Next
					t.Logf("page=%d logical_ids=%v next_after=%d", page+1, got, after)
				} else {
					require(t, p.Next == nil, "prefix last cursor", p.Next)
					t.Logf("page=%d logical_ids=%v next_after=null", page+1, got)
				}
				offset += size
			}
		})
	}
	t.Run("invalid", func(t *testing.T) {
		f := fresh(t)
		for field, values := range map[string][]string{"state": {"all", ""}, "counts": {"0", "true", ""}, "q": {"999.1.1.1", "192.0.2.0/33", "::ffff:192.0.2.1", "::ffff:192.0.2.0/120", "0.0.0.0", "::"}} {
			field := field
			for i, value := range values {
				value := value
				t.Run(fmt.Sprintf("%s-%d", field, i), func(t *testing.T) {
					e := decoded[Error](t, request(t, f.e, "GET", "/api/v1/rules?"+field+"="+url.QueryEscape(value), "ui", "", 400))
					require(t, e.Code == "bad_request" && e.Field == field && e.Code != "mapped_ipv6", value, e)
				})
			}
		}
	})
	t.Run("boundaries", func(t *testing.T) {
		f := fresh(t)
		c5d2Fixture(t, f, false)
		c5d2Fixture(t, f, true)
		for _, pair := range [][2]string{{"0.0.0.0/0", "v4"}, {"::/0", "v6"}, {"  ", ""}, {"192.0.2.7/24", "192.0.2.0/24"}, {"2001:0db8:0000:0000:0000:0000:0000:0000/32", "2001:db8::/32"}, {"2001:db8::7/64", "2001:db8::/64"}} {
			pair := pair
			t.Run(pair[1], func(t *testing.T) {
				got := c5dGet(t, f, "counts=1&q="+url.QueryEscape(pair[0]))
				if pair[1] == "v4" || pair[1] == "v6" {
					require(t, len(got.Items) == 9 && got.Counts["all"] == 9, got)
					for _, r := range got.Items {
						require(t, strings.Contains(r.SrcIP+r.DstIP+r.SrcCIDR+r.DstCIDR, ":") == (pair[1] == "v6"), "family", r)
					}
				} else {
					require(t, reflect.DeepEqual(got, c5dGet(t, f, "counts=1&q="+url.QueryEscape(pair[1]))), "canonical", pair, got)
				}
			})
		}
		t.Run("v4-on-v6", func(t *testing.T) {
			other := fresh(t)
			c5dAdd(t, other, map[string]any{"dst_ip": "2001:db8::1"})
			got := c5dGet(t, other, "counts=1&q=192.0.2.1")
			require(t, len(got.Items) == 0 && got.Counts["all"] == 0, got)
		})
	})
	t.Run("last-cursor", func(t *testing.T) {
		f := fresh(t)
		for i := 1; i <= 15; i++ {
			r := c5dAdd(t, f, map[string]any{"dst_ip": "192.0.2.1", "protocol": "tcp", "dst_port": i, "enabled": i > 7})
			require(t, r.LogicalID == int64(i), "fixed ID", r)
		}
		t.Log("readback=15 matching_logical_ids=1..7 nonmatching_logical_ids=8..15")
		got := c5dGet(t, f, "limit=7&state=disabled&counts=1")
		require(t, len(got.Items) == 7 && got.Next == nil, "last matching page", got)
	})
	t.Run("legacy-bytes", func(t *testing.T) {
		f := fresh(t)
		rows, _, _ := c5d2Fixture(t, f, false)
		t.Run("byte-comparison", func(t *testing.T) {
			for _, after := range []int64{0, 7, 9} {
				old, e := f.s.ListPage(after, 4)
				require(t, e == nil, e)
				want := Page[RuleDTO]{Items: []RuleDTO{}}
				if len(old) > 3 {
					old = old[:3]
					want.NextAfter = old[2].LogicalID
				}
				for _, r := range old {
					want.Items = append(want.Items, ruleDTO(r))
				}
				b, err := json.Marshal(want)
				require(t, err == nil, err)
				w := request(t, f.e, "GET", fmt.Sprintf("/api/v1/rules?limit=3&after=%d", after), "ui", "", 200)
				require(t, string(b) == w.Body.String(), "old ListPage bytes", string(b), w.Body.String())
				t.Logf("after=%d bytes_equal=true bytes=%d", after, len(b))
			}
		})
		for i, query := range []string{"", "q=" + rows[0].ID, "state=disabled", "q=192.0.2.7&state=drop"} {
			query := query
			t.Run(fmt.Sprintf("no-counts-%d", i), func(t *testing.T) {
				got := decoded[map[string]json.RawMessage](t, request(t, f.e, "GET", "/api/v1/rules?"+query, "ui", "", 200))
				require(t, len(got) == 2 && got["items"] != nil && got["next_after"] != nil && got["counts"] == nil, got)
			})
		}
		t.Run("whitelist", func(t *testing.T) {
			got := decoded[map[string]json.RawMessage](t, request(t, f.e, "GET", "/api/v1/whitelist", "ui", "", 200))
			require(t, len(got) == 2 && got["items"] != nil && got["next_after"] != nil, got)
		})
	})
	t.Run("machine", func(t *testing.T) {
		f := fresh(t)
		r := c5dAdd(t, f, map[string]any{"dst_ip": "192.0.2.1"})
		got := c5dGet(t, f, "q="+r.ID+"&state=drop&counts=1")
		require(t, len(got.Items) == 1 && got.Counts["all"] == 1 && permissionOracle["GET /rules"] == "all", got)
		t.Logf("permissionOracle=%d identities=7 matrix=%d", len(permissionOracle), len(permissionOracle)*7)
		require(t, len(permissionOracle)*7 == 329, "matrix")
		real := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		key := real.issue(t, "query-machine").Key
		issued := decoded[CreateResponse](t, real.call(t, "POST", "/rules", key, `{"dst_ip":"192.0.2.1"}`, 201))
		p := decoded[c5dPage](t, real.call(t, "GET", "/rules?q="+issued.ID+"&state=drop&counts=1", key, "", 200))
		require(t, len(p.Items) == 1 && p.Items[0].ID == issued.ID && p.Counts["all"] == 1, "real credential", p)
	})
}

// The oracle uses net.IP containment over the unfiltered HTTP inventory.
func c5dMatch(r RuleDTO, q string) bool {
	if q == "" {
		return true
	}
	if strings.HasPrefix(q, "rule_") {
		return r.ID == q
	}
	a := net.ParseIP(q)
	_, network, _ := net.ParseCIDR(q)
	for _, raw := range []string{r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR} {
		ip := net.ParseIP(raw)
		base, p, _ := net.ParseCIDR(raw)
		if a != nil && (ip.Equal(a) || p != nil && p.Contains(a)) {
			return true
		}
		if network != nil {
			if ip != nil && network.Contains(ip) {
				return true
			}
			if p != nil {
				n, bits := network.Mask.Size()
				m, other := p.Mask.Size()
				if bits == other && m >= n && network.Contains(base) {
					return true
				}
			}
		}
	}
	return false
}
func c5dState(r RuleDTO) string {
	if !r.Enabled {
		return "disabled"
	}
	return r.Action
}

func TestC5D2Random(t *testing.T) {
	f := fresh(t)
	rng := rand.New(rand.NewSource(522902))
	classes := map[string]int{}
	for i := 0; i < 2000; i++ {
		ip, prefix := fmt.Sprintf("10.%d.%d.7", i/256, i%256), fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
		if rng.Intn(2) == 0 {
			ip, prefix = fmt.Sprintf("2001:db8:%x::7", i), fmt.Sprintf("2001:db8:%x::/64", i)
		}
		field, raw := "dst_ip", ip
		if rng.Intn(2) == 0 {
			field, raw = "src_cidr", prefix
		}
		in := map[string]any{field: raw, "enabled": rng.Intn(4) != 0, "src_port": i + 1, "protocol": "tcp"}
		if rng.Intn(3) == 0 {
			in["action"], in["rate_limit"] = "rate_limit", 100
		}
		r := c5dAdd(t, f, in)
		classes[fmt.Sprintf("%v/%s/%s", strings.Contains(raw, ":"), r.Kind, c5dState(r))]++
	}
	all := []RuleDTO{}
	for after := int64(0); ; {
		p := c5dGet(t, f, fmt.Sprintf("limit=1000&after=%d", after))
		all = append(all, p.Items...)
		if p.Next == nil {
			break
		}
		after = *p.Next
	}
	require(t, len(all) == 2000 && len(classes) == 12, "planned=2000 stored/classes", len(all), classes)
	t.Logf("seed=522902 planned=2000 stored=%d readback=2000 classes=%v max_candidates_per_tuple=1 prefixes_non_nested=true", len(all), classes)
	for i := 0; i < 52; i++ {
		r := all[rng.Intn(len(all))]
		q := r.DstIP
		if q == "" {
			base, _, _ := net.ParseCIDR(r.SrcCIDR)
			q = base.String()
		}
		switch i % 4 {
		case 1:
			if r.SrcCIDR != "" {
				q = r.SrcCIDR
			} else if strings.Contains(q, ":") {
				q += "/64"
			} else {
				q += "/24"
			}
		case 2:
			q = r.ID
		case 3:
			q = ""
		}
		for _, state := range []string{"", "drop", "rate_limit", "disabled"} {
			q, state := q, state
			name := state
			if name == "" {
				name = "all"
			}
			t.Run(fmt.Sprintf("q%02d/%s", i, name), func(t *testing.T) {
				want := []RuleDTO{}
				counts := map[string]int{"all": 0, "drop": 0, "rate_limit": 0, "disabled": 0}
				for _, r := range all {
					if c5dMatch(r, q) {
						counts["all"]++
						counts[c5dState(r)]++
						if state == "" || state == c5dState(r) {
							want = append(want, r)
						}
					}
				}
				after, pages := int64(0), 0
				for offset := 0; ; {
					query := fmt.Sprintf("limit=7&after=%d&counts=1&q=%s", after, url.QueryEscape(q))
					if state != "" {
						query += "&state=" + state
					}
					p := c5dGet(t, f, query)
					end := offset + 7
					if end > len(want) {
						end = len(want)
					}
					require(t, reflect.DeepEqual(p.Items, want[offset:end]) && reflect.DeepEqual(p.Counts, counts), "items/counts", q, state, offset, p, counts)
					more := end < len(want)
					require(t, (p.Next != nil) == more, "next iff more", offset, end, len(want), p.Next)
					pages++
					if !more {
						break
					}
					require(t, *p.Next == p.Items[len(p.Items)-1].LogicalID && *p.Next > after, "cursor", p)
					after, offset = *p.Next, end
				}
				t.Logf("q=%q state=%q matches=%d pages=%d counts=%v", q, state, len(want), pages, counts)
			})
		}
	}
}

func TestC5D2Snapshot(t *testing.T) {
	f := fresh(t)
	c5dAdd(t, f, map[string]any{"dst_ip": "192.0.2.1"})
	paused, release, done := make(chan struct{}), make(chan struct{}), make(chan *httptest.ResponseRecorder, 1)
	store.AfterRuleQueryPage = func() { close(paused); <-release }
	defer func() { store.AfterRuleQueryPage = nil }()
	go func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/v1/rules?limit=1000&counts=1&q=192.0.2.1", nil)
		r.Header.Set("X-Xdrop-Actor", "machine:a")
		f.e.ServeHTTP(w, r)
		done <- w
	}()
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("page seam not reached")
	}
	written := make(chan *rules.Error, 1)
	go func() {
		ip, port, protocol := "192.0.2.1", 81, "tcp"
		_, e := f.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{DstIP: &ip, DstPort: &port, Protocol: &protocol})
		written <- e
	}()
	select {
	case e := <-written:
		require(t, e == nil, e)
		t.Log("paused=true concurrent_commit=true")
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("write did not commit during snapshot")
	}
	close(release)
	select {
	case w := <-done:
		require(t, w.Code == 200, w.Body.String())
		p := decoded[c5dPage](t, w)
		require(t, len(p.Items) == 1 && p.Counts["all"] == len(p.Items), "same snapshot", p)
	case <-time.After(5 * time.Second):
		t.Fatal("query did not finish")
	}
	store.AfterRuleQueryPage = nil
	require(t, c5dGet(t, f, "counts=1&q=192.0.2.1").Counts["all"] == 2, "fresh snapshot sees commit")
}

func TestC5D2IDs(t *testing.T) {
	for _, kind := range []string{"overlap", "capacity"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			f := fresh(t)
			want := []string{}
			candidate := `{"src_cidr":"192.0.2.0/25"}`
			code := "cidr_overlap"
			if kind == "overlap" {
				want = append(want, c5dAdd(t, f, map[string]any{"src_cidr": "192.0.2.0/24"}).ID)
			} else {
				code, candidate = "condition_capacity", `{"dst_ip":"192.0.2.1","pkt_len":"100,120,140"}`
				for i := 1; i <= 3; i++ {
					want = append(want, c5dAdd(t, f, map[string]any{"dst_ip": "192.0.2.1", "ttl": strconv.Itoa(i)}).ID)
				}
			}
			e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules", "ui", candidate, 409))
			require(t, e.Code == code && len(e.RuleIDs) == len(want), "rejected code/IDs", e, want)
			for _, id := range e.RuleIDs {
				require(t, strings.Contains(strings.Join(want, ","), id), "occupant", id)
				request(t, f.e, "GET", "/api/v1/rules/"+id, "ui", "", 200)
			}
			sort.Strings(want)
			got := append([]string{}, e.RuleIDs...)
			sort.Strings(got)
			require(t, reflect.DeepEqual(got, want), "complete distinct occupant set", got, want)
			t.Logf("code=%s existing_GET_200=%d rule_ids=%v", e.Code, len(want), e.RuleIDs)
		})
	}
	input := `{"items":[{"src_cidr":"192.0.2.0/24"},{"src_cidr":"192.0.2.0/25"}]}`
	for _, validate := range []bool{false, true} {
		validate := validate
		t.Run(fmt.Sprintf("batch-validate-%v", validate), func(t *testing.T) {
			f := fresh(t)
			path := "/api/v1/rules/batch"
			if validate {
				path += "?validate=1"
			}
			require(t, len(c5dGet(t, f, "").Items) == 0, "independent empty baseline")
			out := decoded[BatchResponse](t, request(t, f.e, "POST", path, "ui", input, 200))
			require(t, len(out.Results) == 2 && out.Results[0].Rule != nil && out.Results[1].Error != nil, "batch shape", out)
			first := out.Results[0].Rule.ID
			if validate {
				first = "batch:0"
			} else {
				request(t, f.e, "GET", "/api/v1/rules/"+first, "ui", "", 200)
			}
			e := out.Results[1].Error
			require(t, e.Code == "cidr_overlap" && reflect.DeepEqual(e.RuleIDs, []string{first, "batch:1"}), "batch IDs", e)
			t.Logf("independent_baseline=0 validate=%v code=%s rule_ids=%v", validate, e.Code, e.RuleIDs)
		})
	}
}

func c5dPerf(t *testing.T, n int) {
	f := fresh(t)
	tx, err := f.db.Begin()
	require(t, err == nil, err)
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
		prefix := fmt.Sprintf("%d.%d.%d.0/24", 10+(i>>16), (i>>8)&255, i&255)
		if i%2 == 1 {
			ip = fmt.Sprintf("2001:db8::%x:%x", i>>16, i&65535)
			prefix = fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&65535)
		}
		in := store.Match{DstIP: ip, Protocol: "tcp", Action: "drop"}
		if i%4 < 2 {
			in.DstIP, in.SrcCIDR = "", prefix
		}
		if i%3 == 0 {
			in.Action, in.RateLimit = "rate_limit", 100
		}
		c, e := rules.Canonicalize(in)
		require(t, e == nil, e)
		r := store.Rule{Match: c.RuleInput, ID: fmt.Sprintf("rule_%032x", i+1), LogicalID: int64(i + 1), Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: i%5 != 0}
		require(t, store.InsertRule(tx, r) == nil, "seed", i)
	}
	_, err = tx.Exec("UPDATE logical_id_hw SET high_water=?", n)
	require(t, err == nil, err)
	require(t, tx.Commit() == nil, "commit")
	var stored int
	require(t, f.db.QueryRow("SELECT count(*) FROM rules").Scan(&stored) == nil && stored == n, "seed count", stored)
	for _, item := range [][2]string{{"all", ""}, {"disabled", "state=disabled"}, {"IP", "q=10.0.2.2"}, {"prefix", "q=10.0.0.0%2F8"}, {"ID", "q=rule_00000000000000000000000000000001"}} {
		item := item
		t.Run(item[0], func(t *testing.T) {
			start := time.Now()
			p := c5dGet(t, f, "limit=100&counts=1&"+item[1])
			elapsed := time.Since(start)
			t.Logf("seed=%d query=%s elapsed=%s items=%d counts=%v", n, item[0], elapsed, len(p.Items), p.Counts)
			require(t, len(p.Counts) == 4, "counts shape", p)
			require(t, len(p.Items) > 0 && p.Counts["all"] > 0, "positive query witness", p)
			if n == 100000 {
				require(t, elapsed <= time.Second, "query exceeded 1s", elapsed)
			}
		})
	}
}
func TestC5D2Perf(t *testing.T) { c5dPerf(t, 100000) }
func TestC5D2Perf500K(t *testing.T) {
	if os.Getenv("XDROP_C5D2O_PERF500K") != "1" {
		t.Skip("set XDROP_C5D2O_PERF500K=1")
	}
	c5dPerf(t, 500000)
}
