package api

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5d3Page struct {
	Items []store.AuditEvent `json:"items"`
	Next  string             `json:"next_cursor"`
}

func c5d3Rows(t *testing.T, f *c4bFixture) []store.AuditEvent {
	t.Helper()
	rows, err := f.db.Reader().Query("SELECT id,at,actor,source,action,target,before,after FROM audit")
	require(t, err == nil, "independent SQL", err)
	defer rows.Close()
	out := []store.AuditEvent{}
	for rows.Next() {
		var e store.AuditEvent
		var before, after *string
		require(t, rows.Scan(&e.ID, &e.At, &e.Actor, &e.Source, &e.Action, &e.Target, &before, &after) == nil, "reference scan")
		if before != nil {
			e.Before = json.RawMessage(*before)
		}
		if after != nil {
			e.After = json.RawMessage(*after)
		}
		out = append(out, e)
	}
	require(t, rows.Err() == nil, "reference rows")
	return out
}

func c5d3Seed(t *testing.T, f *c4bFixture, n int, base time.Time, action func(int) string) {
	t.Helper()
	rng := rand.New(rand.NewSource(530))
	tx, err := f.db.Begin()
	require(t, err == nil, "seed transaction")
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		e := store.AuditEvent{At: base.Add(time.Duration(i/3) * time.Second).Format(store.TimeFormat), Actor: "user:alice", Source: "192.0.2.1", Action: action(i), Target: fmt.Sprintf("seed:%d:%d", i, rng.Uint32())}
		require(t, store.InsertAudit(tx, e) == nil, "seed insert", i)
	}
	require(t, tx.Commit() == nil, "seed commit")
}

func c5d3Select(all []store.AuditEvent, action, from, to string, desc bool) []store.AuditEvent {
	out := []store.AuditEvent{}
	for _, e := range all {
		if (action == "" || e.Action == action) && (from == "" || e.At >= from) && (to == "" || e.At < to) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if desc {
			i, j = j, i
		}
		return out[i].At < out[j].At || out[i].At == out[j].At && out[i].ID < out[j].ID
	})
	return out
}

func c5d3Cursor(e store.AuditEvent) string {
	b, _ := json.Marshal(struct {
		At string
		ID int64
	}{e.At, e.ID})
	return base64.RawURLEncoding.EncodeToString(b)
}

func c5d3Pages(t *testing.T, f *c4bFixture, query string, limit int, want []store.AuditEvent, emptyTwin bool) {
	t.Helper()
	cursor, seen := "", []store.AuditEvent{}
	for offset := 0; ; offset += limit {
		end := offset + limit
		if end > len(want) {
			end = len(want)
		}
		expected := c5d3Page{Items: append([]store.AuditEvent{}, want[offset:end]...)}
		if end < len(want) {
			expected.Next = c5d3Cursor(want[end-1])
		}
		path := fmt.Sprintf("/audit?limit=%d&cursor=%s%s", limit, url.QueryEscape(cursor), query)
		w := f.call(t, "GET", path, f.cookie, "", 200)
		if emptyTwin {
			twin := f.call(t, "GET", path+"&action=", f.cookie, "", 200)
			require(t, bytes.Equal(w.Body.Bytes(), twin.Body.Bytes()), "omitted/empty page bytes")
		}
		b, err := json.Marshal(expected)
		require(t, err == nil && bytes.Equal(w.Body.Bytes(), b), "independent page byte baseline", offset, "want rows", len(expected.Items), "got", w.Body.String())
		got := decoded[c5d3Page](t, w)
		require(t, (got.Next != "") == (end < len(want)), "next_cursor iff more matches")
		seen = append(seen, got.Items...)
		cursor = got.Next
		if cursor == "" {
			break
		}
	}
	require(t, c4aJSON(seen) == c4aJSON(want), "complete ordered concatenation")
}

func c5d3Export(t *testing.T, f *c4bFixture, query, format string, want []store.AuditEvent) *httptest.ResponseRecorder {
	t.Helper()
	w := f.call(t, "GET", "/audit/export?"+query+"&format="+format, f.cookie, "", 200)
	if format == "json" {
		got := decoded[[]store.AuditEvent](t, w)
		require(t, c4aJSON(got) == c4aJSON(want), "export JSON rows/order", len(got), len(want))
	} else {
		rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		require(t, err == nil && len(rows) == len(want)+1, "export CSV count", len(rows), len(want)+1)
		require(t, reflect.DeepEqual(rows[0], strings.Split("id,at,actor,source,action,target,before,after", ",")), "CSV header")
		for i, e := range want {
			expected := []string{fmt.Sprint(e.ID), e.At, e.Actor, e.Source, e.Action, e.Target, string(e.Before), string(e.After)}
			require(t, reflect.DeepEqual(rows[i+1], expected), "export CSV rows/order", i)
		}
	}
	return w
}

func TestC5D3Audit(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	initial := len(c5d3Rows(t, f))
	c5d3Seed(t, f, 338, f.now, func(i int) string { return c4bActions[i%len(c4bActions)] })
	all := c5d3Rows(t, f)
	require(t, initial > 0 && len(all) == 338+initial, "independent reference includes initialization")
	t.Logf("direct SQL rows=%d seeded=338 initialization=%d seed=530", len(all), initial)
	counts := map[string]int{}
	for _, e := range all {
		counts[e.Action]++
	}
	require(t, len(counts) == 26 && counts["auth.login"] >= 5 && counts["auth.login_failed"] >= 5, "action witnesses")
	for _, action := range c4bActions {
		t.Logf("action=%s count=%d", action, counts[action])
	}
	ordered := c5d3Select(all, "", "", "", false)
	ties, interleaved := 0, 0
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].At == ordered[i].At {
			ties++
		}
		if ordered[i-1].Action == "auth.login" && ordered[i].Action == "auth.login_failed" {
			interleaved++
		}
	}
	require(t, ties > 0 && interleaved >= 5, "duplicate seconds and interleaved login witnesses")
	t.Logf("duplicate_seconds_pairs=%d interleaved_login_pairs=%d", ties, interleaved)
	previous, pairs := -1, 0
	for i, e := range ordered {
		if e.Action == "node.delete" {
			if previous >= 0 {
				gap := i - previous - 1
				require(t, gap >= 8, "sparse gap")
				t.Logf("sparse action=node.delete adjacent_pair=%d nonmatches=%d", pairs, gap)
				pairs++
			}
			previous = i
		}
	}
	require(t, pairs >= 2, "sparse adjacent pairs")
	for _, action := range c4bActions {
		action := action
		for _, limit := range []int{1, 3, 7} {
			limit := limit
			t.Run(fmt.Sprintf("pages/%s/%d", action, limit), func(t *testing.T) {
				c5d3Pages(t, f, "&action="+url.QueryEscape(action), limit, c5d3Select(all, action, "", "", true), false)
			})
		}
	}
	t.Run("prefix-separation", func(t *testing.T) {
		for _, action := range []string{"auth.login", "auth.login_failed"} {
			c5d3Pages(t, f, "&action="+action, 7, c5d3Select(all, action, "", "", true), false)
		}
	})
	t.Run("empty-baseline", func(t *testing.T) {
		c5d3Pages(t, f, "", 7, c5d3Select(all, "", "", "", true), true)
	})
	from, to := f.now.Format(store.TimeFormat), f.now.Add(40*time.Second).Format(store.TimeFormat)
	rangeQuery := "from=" + from + "&to=" + to
	t.Run("range", func(t *testing.T) {
		matches := c5d3Select(all, "auth.login", "", "", false)
		lo, hi := matches[1].At, matches[3].At
		require(t, lo < hi, "inclusive/exclusive matching boundary witnesses")
		c5d3Pages(t, f, "&from="+lo+"&to="+hi+"&action=auth.login", 3, c5d3Select(all, "auth.login", lo, hi, true), false)
	})
	for _, raw := range []string{"no.such", "%20", "AUTH.LOGIN", "%2561uth.login", "auth.login%20", "rule.*", "auth.login%2Cauth.login_failed", "%27%20OR%201%3D1--", "%61uth.login"} {
		raw := raw
		t.Run("literal/"+raw, func(t *testing.T) {
			action, err := url.QueryUnescape(raw)
			require(t, err == nil, "query fixture")
			c5d3Pages(t, f, "&action="+raw, 7, c5d3Select(all, action, "", "", true), false)
		})
	}
	t.Run("cursor-switch", func(t *testing.T) {
		login := c5d3Select(all, "auth.login", "", "", true)
		w := f.call(t, "GET", "/audit?action=auth.login&limit=1", f.cookie, "", 200)
		cursor := decoded[c5d3Page](t, w).Next
		require(t, cursor == c5d3Cursor(login[0]), "cursor shape")
		want := []store.AuditEvent{}
		for _, e := range c5d3Select(all, "auth.login_failed", "", "", true) {
			if e.At < login[0].At || e.At == login[0].At && e.ID < login[0].ID {
				want = append(want, e)
			}
		}
		w = f.call(t, "GET", "/audit?action=auth.login_failed&limit=1000&cursor="+cursor, f.cookie, "", 200)
		require(t, w.Body.String() == c4aJSON(c5d3Page{Items: want}), "cursor independent of action")
	})
	for _, format := range []string{"csv", "json"} {
		format := format
		t.Run("export-filter/"+format, func(t *testing.T) {
			c5d3Export(t, f, rangeQuery+"&action=auth.login", format, c5d3Select(all, "auth.login", from, to, false))
		})
		t.Run("export-empty/"+format, func(t *testing.T) {
			query := "from=" + from + "&to=2026-10-13T00:00:00Z"
			want := c5d3Select(all, "", "", "", false)
			a := c5d3Export(t, f, query, format, want)
			b := c5d3Export(t, f, query+"&action=", format, want)
			require(t, bytes.Equal(a.Body.Bytes(), b.Body.Bytes()) && a.Header().Get("Content-Disposition") == b.Header().Get("Content-Disposition"), "export omitted/empty bytes and filename")
			require(t, a.Header().Get("Content-Disposition") == fmt.Sprintf(`attachment; filename="xdrop-audit-%s-2026-10-13T00:00:00Z.%s"`, from, format), "unchanged filename")
		})
	}
	t.Run("operator", func(t *testing.T) {
		f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"ops", f.pw}, "operator"}), 201)
		cookie := f.login(t, "ops", f.pw)
		me := decoded[IdentityDTO](t, f.call(t, "GET", "/auth/me", cookie, "", 200))
		require(t, me.Role == "operator", "operator identity witness")
		t.Logf("auth/me role=%s", me.Role)
		f.call(t, "GET", "/audit?action=auth.login", cookie, "", 200)
		w := f.call(t, "GET", "/audit/export?"+rangeQuery+"&format=json&action=auth.login", cookie, "", 403)
		require(t, decoded[Error](t, w).Code == "admin_required", "export operator denied")
	})
}

func TestC5D3LegacyDelegates(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	c5d3Seed(t, f, 26, f.now, func(i int) string { return c4bActions[i] })
	all := c5d3Rows(t, f)
	desc, asc := c5d3Select(all, "", "", "", true), c5d3Select(all, "", "", "", false)
	page, e1 := store.AuditPage(f.db.Reader(), "", "", "", 0, 1000)
	after, e2 := store.AuditAfter(f.db.Reader(), "", "", "", 0, 1000)
	svc, e3 := f.s.AuditPage("", "", "", 0, 1000)
	exported := []store.AuditEvent{}
	e4 := f.s.AuditExport("", "", func(e store.AuditEvent) error { exported = append(exported, e); return nil })
	require(t, e1 == nil && e2 == nil && e3 == nil && e4 == nil, "legacy delegates")
	for name, got := range map[string][2][]store.AuditEvent{"store.AuditPage": {page, desc}, "store.AuditAfter": {after, asc}, "Service.AuditPage": {svc, desc}, "Service.AuditExport": {exported, asc}} {
		if c4aJSON(got[0]) != c4aJSON(got[1]) {
			t.Fatalf("%s unfiltered rows=%d want=%d", name, len(got[0]), len(got[1]))
		}
	}
	t.Logf("legacy delegates rows=%d", len(all))
}

func TestC5D3ExportCrossPage(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	base := f.now.Add(24 * time.Hour)
	c5d3Seed(t, f, 1102, base, func(i int) string {
		if i == 0 || i == 1001 {
			return "rule.delete"
		}
		return "rule.create"
	})
	from, to := base.Format(store.TimeFormat), base.Add(time.Hour).Format(store.TimeFormat)
	all := c5d3Rows(t, f)
	window := c5d3Select(all, "", from, to, false)
	require(t, len(window) == 1102, "cross page count")
	for i, e := range window {
		isB := i == 0 || i == 1001
		require(t, (e.Action == "rule.delete") == isB, "B positions", i)
		if isB {
			t.Logf("B position=%d id=%d at=%s preceding_A=%d", i, e.ID, e.At, i-i/1001)
		}
	}
	want := c5d3Select(all, "rule.create", from, to, false)
	require(t, len(want) == 1100, "1100 matching A")
	for _, format := range []string{"csv", "json"} {
		format := format
		t.Run(format, func(t *testing.T) {
			c5d3Export(t, f, "from="+from+"&to="+to+"&action=rule.create", format, want)
		})
	}
}

func TestC5D3Performance(t *testing.T) {
	for _, n := range []int{200000, 2000000} {
		n := n
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if n == 2000000 && os.Getenv("XDROP_C5D3_PERF_2M") == "" {
				t.Skip("set XDROP_C5D3_PERF_2M=1 for main-session performance reading")
			}
			f := c4bFresh(t, c4bCorpus())
			c5d3Seed(t, f, n, f.now, func(i int) string {
				if i%(n/10) == 0 {
					return "rule.delete"
				}
				return "rule.create"
			})
			start := time.Now()
			w := f.call(t, "GET", "/audit?action=rule.delete&limit=100", f.cookie, "", 200)
			elapsed := time.Since(start)
			t.Logf("rows=%d rare=10 evenly_spaced=%d elapsed=%s", n, n/10, elapsed)
			page := decoded[c5d3Page](t, w)
			require(t, len(page.Items) == 10 && page.Next == "", "rare result count")
			for _, e := range page.Items {
				require(t, e.Action == "rule.delete", "rare action")
			}
			bound := time.Second
			if n == 2000000 {
				bound = 3 * time.Second
			}
			require(t, elapsed <= bound, "rare action performance", elapsed, bound)
		})
	}
}
