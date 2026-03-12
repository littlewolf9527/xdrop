package model

import (
	"time"
)

// Whitelist whitelist model
type Whitelist struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	SrcIP     string    `json:"src_ip,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstPort   int       `json:"dst_port,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// WhitelistRequest add whitelist entry request
type WhitelistRequest struct {
	Name     string `json:"name,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// ToNodeWhitelist converts to Node API format
func (w *Whitelist) ToNodeWhitelist() map[string]interface{} {
	entry := map[string]interface{}{
		"id": w.ID, // send Controller ID for Node to use
	}
	if w.SrcIP != "" {
		entry["src_ip"] = w.SrcIP
	}
	if w.DstIP != "" {
		entry["dst_ip"] = w.DstIP
	}
	if w.SrcPort > 0 {
		entry["src_port"] = w.SrcPort
	}
	if w.DstPort > 0 {
		entry["dst_port"] = w.DstPort
	}
	if w.Protocol != "" {
		entry["protocol"] = w.Protocol
	}
	return entry
}
