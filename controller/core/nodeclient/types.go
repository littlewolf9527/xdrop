// Package nodeclient implements the bounded, non-redirecting protocol 11 client.
package nodeclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Key holds its bytes privately, including when a NodeSpec is formatted.
type Key struct{ value string }

func Secret(value string) Key               { return Key{value: value} }
func (k Key) Format(s fmt.State, verb rune) { io.WriteString(s, "[redacted]") }
func (k Key) MarshalJSON() ([]byte, error)  { return []byte(`"[redacted]"`), nil }

type NodeSpec struct {
	Name, BaseURL string
	Key           Key
}

type Route string

const (
	ProbeRoute     Route = "/"
	HealthRoute    Route = "/api/v1/health"
	StatsRoute     Route = "/api/v1/stats"
	RulesRoute     Route = "/api/v1/rules"
	HitsRoute      Route = "/api/v1/rules/hits"
	WhitelistRoute Route = "/api/v1/whitelist"
	CommitRoute    Route = "/api/v1/rules/commit"
	AtomicRoute    Route = "/api/v1/sync/atomic"
	SyncWLRoute    Route = "/api/v1/sync/whitelist"
)

type Options struct {
	Transport http.RoundTripper
	Timeouts  map[Route]time.Duration
	Limits    map[Route]int64
}

type CallError struct {
	Route      Route
	Kind       string
	HTTPStatus int
	Code       string
	Message    string
	Body       map[string]any
}

func (e *CallError) Error() string {
	return fmt.Sprintf("%s: %s (HTTP %d, %s): %s", e.Route, e.Kind, e.HTTPStatus, e.Code, e.Message)
}

type ProbeResult string

const (
	OK           ProbeResult = "ok"
	Incompatible ProbeResult = "incompatible"
	Unreachable  ProbeResult = "unreachable"
)

type Rule struct {
	ID           string  `json:"id"`
	LogicalID    uint32  `json:"logical_id"`
	SrcIP        string  `json:"src_ip,omitempty"`
	DstIP        string  `json:"dst_ip,omitempty"`
	SrcCIDR      string  `json:"src_cidr,omitempty"`
	DstCIDR      string  `json:"dst_cidr,omitempty"`
	SrcPort      int     `json:"src_port,omitempty"`
	DstPort      int     `json:"dst_port,omitempty"`
	Protocol     string  `json:"protocol,omitempty"`
	Action       string  `json:"action,omitempty"`
	RateLimit    int64   `json:"rate_limit,omitempty"`
	TCPFlags     string  `json:"tcp_flags,omitempty"`
	MatchAnomaly int     `json:"match_anomaly,omitempty"`
	TTL          *string `json:"ttl,omitempty"`
	DSCP         *string `json:"dscp,omitempty"`
	ICMPType     *string `json:"icmp_type,omitempty"`
	ICMPCode     *string `json:"icmp_code,omitempty"`
	Fragment     *string `json:"fragment,omitempty"`
	PktLen       *string `json:"pkt_len,omitempty"`
}

type ReadRule struct {
	Rule
	PktLenMin int            `json:"pkt_len_min,omitempty"`
	PktLenMax int            `json:"pkt_len_max,omitempty"`
	Stats     map[string]any `json:"stats,omitempty"`
}
type Entry struct {
	ID       string `json:"id"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}
type Group struct {
	Key   json.RawMessage `json:"key"`
	Rules []Rule          `json:"rules"`
}
type Health struct {
	Status          string `json:"status"`
	RulesSynced     bool   `json:"rules_synced"`
	WhitelistSynced bool   `json:"whitelist_synced"`
}
type RulesPage struct {
	Rules      []ReadRule `json:"rules"`
	Pagination struct {
		Page, Limit, Total, Pages int
	} `json:"pagination"`
}

type RuleHit struct {
	RuleID     string `json:"rule_id"`
	LogicalID  uint32 `json:"logical_id"`
	MatchCount uint64 `json:"match_count"`
	DropCount  uint64 `json:"drop_count"`
	MatchBytes uint64 `json:"match_bytes"`
	DropBytes  uint64 `json:"drop_bytes"`
	LastHitNS  uint64 `json:"last_hit_ns"`
}

type HitsResponse struct {
	NowNS     uint64    `json:"now_ns"`
	Truncated bool      `json:"truncated"`
	Scanned   uint64    `json:"scanned"`
	Hits      []RuleHit `json:"hits"`
}
type Whitelist struct {
	Entries []Entry `json:"entries"`
	Count   int     `json:"count"`
}
type CommitReply struct {
	Code   string `json:"code"`
	Groups []struct {
		Index  int    `json:"index"`
		Result string `json:"result"`
	} `json:"groups"`
}
type Rejection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}
type AtomicReply struct {
	Success   bool        `json:"success"`
	Added     int         `json:"added"`
	Failed    int         `json:"failed"`
	Rules     int         `json:"rules"`
	CIDRRules int         `json:"cidr_rules"`
	Rejected  []Rejection `json:"rejected"`
}
type WhitelistReply struct {
	Total  int `json:"total"`
	Failed int `json:"failed"`
}
