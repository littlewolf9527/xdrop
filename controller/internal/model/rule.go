package model

import (
	"time"
)

// Rule rule model
type Rule struct {
	ID        string     `json:"id"`
	Name      string     `json:"name,omitempty"`
	SrcIP     string     `json:"src_ip,omitempty"`
	DstIP     string     `json:"dst_ip,omitempty"`
	SrcCIDR   string     `json:"src_cidr,omitempty"` // CIDR notation (e.g. "10.0.0.0/8")
	DstCIDR   string     `json:"dst_cidr,omitempty"` // CIDR notation (e.g. "192.168.0.0/16")
	SrcPort   int        `json:"src_port,omitempty"`
	DstPort   int        `json:"dst_port,omitempty"`
	Protocol  string     `json:"protocol,omitempty"`
	Action    string     `json:"action"`
	RateLimit int        `json:"rate_limit,omitempty"`
	PktLenMin int        `json:"pkt_len_min,omitempty"` // L3 packet length min (0=no limit)
	PktLenMax int        `json:"pkt_len_max,omitempty"` // L3 packet length max (0=no limit)
	TcpFlags  string     `json:"tcp_flags,omitempty"`   // TCP flags filter (e.g. "SYN,!ACK")
	// MatchAnomaly is a bitmask (bit0=bad_fragment bit1=invalid). 0=don't
	// check (default; legacy rules behave unchanged). v2.6 Phase 4.
	MatchAnomaly int        `json:"match_anomaly,omitempty"`
	Source       string     `json:"source,omitempty"`
	Comment      string     `json:"comment,omitempty"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// RuleRequest add/update rule request
type RuleRequest struct {
	Name      string `json:"name,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	SrcCIDR   string `json:"src_cidr,omitempty"` // CIDR notation (e.g. "10.0.0.0/8")
	DstCIDR   string `json:"dst_cidr,omitempty"` // CIDR notation (e.g. "192.168.0.0/16")
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Action    string `json:"action"`
	RateLimit int    `json:"rate_limit,omitempty"`
	PktLenMin int    `json:"pkt_len_min,omitempty"` // L3 packet length min (0=no limit)
	PktLenMax int    `json:"pkt_len_max,omitempty"` // L3 packet length max (0=no limit)
	TcpFlags  *string `json:"tcp_flags,omitempty"`   // TCP flags filter; pointer for tri-state: nil=omit, ""=clear, "SYN"=set
	// Decoder is an input-only syntactic sugar (v2.6 Phase 2). When set, the
	// service layer's normalizeDecoder expands it into protocol / tcp_flags
	// / match_anomaly before storage. Rule.Protocol / Rule.TcpFlags /
	// Rule.MatchAnomaly are what persists — the GET response never exposes a
	// Decoder field.
	// Allowed values: tcp_ack / tcp_rst / tcp_fin (v1.3 Tier 1), bad_fragment
	// / invalid (v2.6 Phase 4). Mutually exclusive with the underlying fields.
	Decoder string `json:"decoder,omitempty"`
	// MatchAnomaly is normally set via Decoder. Explicit input is rejected by
	// normalizeDecoder as mutually exclusive with decoder (prevents silent
	// drift). 0=don't check.
	MatchAnomaly int     `json:"match_anomaly,omitempty"`
	ExpiresIn    string  `json:"expires_in,omitempty"` // "1h", "30m", "24h"
	Source       string  `json:"source,omitempty"`
	Comment      string  `json:"comment,omitempty"`
}

// ToNodeRule converts to Node API format
func (r *Rule) ToNodeRule() map[string]interface{} {
	rule := map[string]interface{}{
		"id":     r.ID, // send Controller ID for Node to use
		"action": r.Action,
	}
	if r.SrcIP != "" {
		rule["src_ip"] = r.SrcIP
	}
	if r.DstIP != "" {
		rule["dst_ip"] = r.DstIP
	}
	if r.SrcPort > 0 {
		rule["src_port"] = r.SrcPort
	}
	if r.DstPort > 0 {
		rule["dst_port"] = r.DstPort
	}
	if r.Protocol != "" && r.Protocol != "all" {
		rule["protocol"] = r.Protocol
	}
	if r.RateLimit > 0 {
		rule["rate_limit"] = r.RateLimit
	}
	if r.PktLenMin > 0 {
		rule["pkt_len_min"] = r.PktLenMin
	}
	if r.PktLenMax > 0 {
		rule["pkt_len_max"] = r.PktLenMax
	}
	if r.TcpFlags != "" {
		rule["tcp_flags"] = r.TcpFlags
	}
	if r.SrcCIDR != "" {
		rule["src_cidr"] = r.SrcCIDR
	}
	if r.DstCIDR != "" {
		rule["dst_cidr"] = r.DstCIDR
	}
	if r.MatchAnomaly != 0 {
		rule["match_anomaly"] = r.MatchAnomaly
	}
	return rule
}
