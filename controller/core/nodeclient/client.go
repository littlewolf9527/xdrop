package nodeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	name, base, key string
	http            *http.Client
	timeouts        map[Route]time.Duration
	limits          map[Route]int64
}

func New(spec NodeSpec, opts Options) (*Client, error) {
	u, err := url.Parse(spec.BaseURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid node base URL")
	}
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	c := &Client{name: spec.Name, base: strings.TrimRight(spec.BaseURL, "/"), key: spec.Key.value,
		http:     &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeouts: map[Route]time.Duration{}, limits: map[Route]int64{}}
	for _, route := range []Route{ProbeRoute, HealthRoute, StatsRoute, RulesRoute, HitsRoute, WhitelistRoute, CommitRoute, AtomicRoute, SyncWLRoute} {
		d := 30 * time.Second
		switch route {
		case ProbeRoute, HealthRoute:
			d = 3 * time.Second
		case StatsRoute, HitsRoute:
			d = 5 * time.Second
		case AtomicRoute:
			d = 150 * time.Second
		}
		if opts.Timeouts[route] > 0 {
			d = opts.Timeouts[route]
		}
		c.timeouts[route] = d
		c.limits[route] = opts.Limits[route]
	}
	return c, nil
}

func (c Client) Format(s fmt.State, verb rune) { io.WriteString(s, "nodeclient.Client") }
func (c Client) MarshalJSON() ([]byte, error)  { return []byte(`{}`), nil }

func (c *Client) limit(route Route, size, groups int) int64 {
	if v := c.limits[route]; v > 0 {
		return v
	}
	switch route {
	case ProbeRoute, HealthRoute:
		return 64 << 10
	case StatsRoute, SyncWLRoute:
		return 1 << 20
	case RulesRoute:
		return 16 << 20
	case HitsRoute:
		return 4 << 20
	case WhitelistRoute:
		return 32 << 20
	case CommitRoute:
		return 4<<20 + 64*int64(groups)
	default:
		return max(4<<20, 2*int64(size))
	}
}

func (c *Client) scrub(s string) string {
	if c.key != "" {
		return strings.ReplaceAll(s, c.key, "[redacted]")
	}
	return s
}
func (c *Client) scrubValue(v any) any {
	switch x := v.(type) {
	case string:
		return c.scrub(x)
	case map[string]any:
		r := map[string]any{}
		for k, v := range x {
			r[c.scrub(k)] = c.scrubValue(v)
		}
		return r
	case []any:
		for i := range x {
			x[i] = c.scrubValue(x[i])
		}
	}
	return v
}

func (c *Client) call(parent context.Context, route Route, query string, body []byte, groups int, out any) *CallError {
	ctx, cancel := context.WithTimeout(parent, c.timeouts[route])
	defer cancel()
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	e := &CallError{Route: route}
	req, err := http.NewRequestWithContext(ctx, method, c.base+string(route)+query, bytes.NewReader(body))
	if err != nil {
		e.Kind, e.Message = "transport", "cannot construct request"
		return e
	}
	if route != ProbeRoute && route != HealthRoute {
		req.Header.Set("X-API-Key", c.key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		e.Kind, e.Message = "transport", c.scrub(err.Error())
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			e.Kind = "timeout"
		}
		e.Message = e.Message[:min(512, len(e.Message))]
		return e
	}
	defer resp.Body.Close()
	e.HTTPStatus = resp.StatusCode
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		e.Kind = "redirect"
		return e
	}
	if route == ProbeRoute && resp.StatusCode != 200 {
		e.Kind = "status"
		return e
	}
	limit := c.limit(route, len(body), groups)
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(data)) > limit {
		e.Kind = "too_large"
		return e
	}
	if err != nil {
		e.Kind = "transport"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			e.Kind = "timeout"
		}
		return e
	}
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !success && len(bytes.TrimSpace(data)) == 0 {
		e.Kind = "status"
		return e
	}
	var object map[string]json.RawMessage
	if uniqueJSON(data) != nil || json.Unmarshal(data, &object) != nil || object == nil {
		e.Kind = "invalid"
		return e
	}
	if !success {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var parsed map[string]any
		if decoder.Decode(&parsed) != nil {
			e.Kind = "invalid"
			return e
		}
		e.Body = c.scrubValue(parsed).(map[string]any)
		e.Code, _ = e.Body["code"].(string)
		e.Message, _ = e.Body["error"].(string)
		if e.Message == "" {
			e.Message, _ = e.Body["message"].(string)
		}
		e.Message = e.Message[:min(512, len(e.Message))]
		e.Kind = "status"
		return e
	}
	if !shape(route, object) {
		e.Kind = "invalid"
		return e
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(out) != nil {
		e.Kind = "invalid"
		return e
	}
	// Only diagnostic strings are scrubbed; rule identity/content stays intact.
	switch result := out.(type) {
	case *AtomicReply:
		for i := range result.Rejected {
			result.Rejected[i].Reason = c.scrub(result.Rejected[i].Reason)
		}
	case *RulesPage:
		for i := range result.Rules {
			result.Rules[i].Stats = c.scrubValue(result.Rules[i].Stats).(map[string]any)
		}
	case *map[string]any:
		if route == StatsRoute {
			*result = c.scrubValue(*result).(map[string]any)
		}
	}
	return nil
}

// Token traversal rejects duplicate keys at every depth before typed decoding.
func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func() error
	value = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return errors.New("duplicate JSON key")
					}
					seen[name] = true
				}
				if err := value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// fields distinguishes absent/null from legitimate zero values before decoding.
func fields(m map[string]json.RawMessage, names string, kind byte) bool {
	for _, name := range strings.Fields(names) {
		raw := bytes.TrimSpace(m[name])
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			return false
		}
		switch kind {
		case 'u':
			var n uint64
			if json.Unmarshal(raw, &n) != nil {
				return false
			}
		case 'b':
			var b bool
			if json.Unmarshal(raw, &b) != nil {
				return false
			}
		case 'i':
			var n int64
			if json.Unmarshal(raw, &n) != nil {
				return false
			}
		case 's', 'k':
			var s string
			if json.Unmarshal(raw, &s) != nil || (kind == 'k' && s == "") {
				return false
			}
		case 'n':
			var v any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if d.Decode(&v) != nil {
				return false
			}
			if _, ok := v.(json.Number); !ok {
				return false
			}
		}
	}
	return true
}

func shape(route Route, m map[string]json.RawMessage) bool {
	required := map[Route]string{
		HitsRoute:   "now_ns truncated scanned hits",
		HealthRoute: "status", StatsRoute: "total_packets dropped_packets passed_packets",
		RulesRoute: "rules pagination", WhitelistRoute: "entries count", CommitRoute: "code groups",
		AtomicRoute: "success added failed rules cidr_rules rejected", SyncWLRoute: "total failed",
	}
	for _, key := range strings.Fields(required[route]) {
		v, ok := m[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	if route == HealthRoute {
		var status string
		if json.Unmarshal(m["status"], &status) != nil || (status != "healthy" && status != "degraded") {
			return false
		}
		if status == "degraded" {
			for _, key := range []string{"rules_synced", "whitelist_synced"} {
				var b bool
				if len(m[key]) == 0 || string(m[key]) == "null" || json.Unmarshal(m[key], &b) != nil {
					return false
				}
			}
		}
	}
	if route == StatsRoute && !fields(m, required[route], 'n') {
		return false
	}
	if route == HitsRoute && (!fields(m, "now_ns scanned", 'u') || !fields(m, "truncated", 'b')) {
		return false
	}
	if route == RulesRoute {
		var pagination map[string]json.RawMessage
		if json.Unmarshal(m["pagination"], &pagination) != nil || !fields(pagination, "page limit total pages", 'i') {
			return false
		}
	}
	array := map[Route]string{CommitRoute: "groups", RulesRoute: "rules", HitsRoute: "hits", WhitelistRoute: "entries", AtomicRoute: "rejected"}[route]
	if array != "" {
		var items []map[string]json.RawMessage
		if json.Unmarshal(m[array], &items) != nil {
			return false
		}
		for _, item := range items {
			ok := false
			switch route {
			case HitsRoute:
				ok = fields(item, "rule_id", 'k') && fields(item, "logical_id match_count drop_count match_bytes drop_bytes last_hit_ns", 'u')
			case CommitRoute:
				ok = fields(item, "index", 'i') && fields(item, "result", 's')
			case RulesRoute:
				ok = fields(item, "id", 'k') && fields(item, "logical_id", 'i') && fields(item, "protocol action", 's')
			case WhitelistRoute:
				ok = fields(item, "id", 's')
			case AtomicRoute:
				ok = fields(item, "id reason", 's')
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

var decimal = regexp.MustCompile(`^[0-9]+$`)

func (c *Client) Probe(ctx context.Context) (ProbeResult, *CallError) {
	var obj map[string]json.RawMessage
	e := c.call(ctx, ProbeRoute, "", nil, 0, &obj)
	if e != nil {
		if e.HTTPStatus == 200 && (e.Kind == "invalid" || e.Kind == "too_large") {
			return Incompatible, e
		}
		return Unreachable, e
	}
	raw := string(obj["sync_protocol"])
	n, err := strconv.ParseInt(raw, 10, 64)
	if !decimal.MatchString(raw) || err != nil || n != 11 {
		return Incompatible, nil
	}
	return OK, nil
}

func (c *Client) Health(ctx context.Context) (r Health, e *CallError) {
	e = c.call(ctx, HealthRoute, "", nil, 0, &r)
	if e == nil && r.Status == "healthy" {
		r.RulesSynced, r.WhitelistSynced = true, true
	}
	return
}
func (c *Client) Stats(ctx context.Context) (r map[string]any, e *CallError) {
	e = c.call(ctx, StatsRoute, "", nil, 0, &r)
	return
}
func (c *Client) Rules(ctx context.Context, page, limit int) (r RulesPage, e *CallError) {
	e = c.call(ctx, RulesRoute, fmt.Sprintf("?page=%d&limit=%d", page, limit), nil, 0, &r)
	return
}

func (c *Client) Hits(ctx context.Context, sinceNS uint64) (r HitsResponse, err error) {
	if e := c.call(ctx, HitsRoute, "?since_ns="+strconv.FormatUint(sinceNS, 10), nil, 0, &r); e != nil {
		return r, e
	}
	return r, nil
}
func (c *Client) Whitelist(ctx context.Context) (r Whitelist, e *CallError) {
	e = c.call(ctx, WhitelistRoute, "", nil, 0, &r)
	return
}
func (c *Client) Commit(ctx context.Context, body []byte, groups int) (r CommitReply, e *CallError) {
	e = c.call(ctx, CommitRoute, "", body, groups, &r)
	return
}
func (c *Client) Atomic(ctx context.Context, body []byte) (r AtomicReply, e *CallError) {
	e = c.call(ctx, AtomicRoute, "", body, 0, &r)
	return
}
func (c *Client) SyncWhitelist(ctx context.Context, body []byte) (r WhitelistReply, e *CallError) {
	e = c.call(ctx, SyncWLRoute, "", body, 0, &r)
	return
}
