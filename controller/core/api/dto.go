package api

import (
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

// MatchDTO retains the service's canonical field names without exposing rows.
type MatchDTO store.Match
type RuleDTO struct {
	MatchDTO
	ID        string  `json:"id"`
	LogicalID int64   `json:"logical_id"`
	Kind      string  `json:"kind"`
	GroupKey  string  `json:"group_key"`
	CondKey   string  `json:"cond_key"`
	Enabled   bool    `json:"enabled"`
	Comment   string  `json:"comment"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
	ExpiresAt *string `json:"expires_at"`
	CreatedBy string  `json:"created_by"`
	UpdatedBy string  `json:"updated_by"`
}

func ruleDTO(r store.Rule) RuleDTO {
	return RuleDTO{MatchDTO(r.Match), r.ID, r.LogicalID, r.Kind, r.GroupKey, r.CondKey, r.Enabled, r.Comment, r.CreatedAt, r.UpdatedAt, r.ExpiresAt, r.CreatedBy, r.UpdatedBy}
}

type WhitelistDTO struct {
	ID        string `json:"id"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

func whitelistDTO(w store.Whitelist) WhitelistDTO {
	return WhitelistDTO{w.ID, w.SrcIP, w.DstIP, w.SrcPort, w.DstPort, w.Protocol, w.Comment, w.CreatedAt, w.CreatedBy}
}

type RejectedDTO struct {
	Key     string   `json:"key,omitempty"`
	ID      string   `json:"id,omitempty"`
	Code    string   `json:"code,omitempty"`
	Error   string   `json:"error,omitempty"`
	RuleIDs []string `json:"rule_ids,omitempty"`
}
type SideDTO struct {
	State        string        `json:"state"`
	Reason       string        `json:"reason"`
	Since        string        `json:"since"`
	ConfirmedGen uint64        `json:"confirmed_gen"`
	Confirmable  bool          `json:"confirmable"`
	Rejected     []RejectedDTO `json:"rejected"`
}

func sideDTO(s orch.SideStatus) SideDTO {
	out := SideDTO{s.State, s.Reason, stamp(s.Since), s.ConfirmedGen, s.Confirmable, []RejectedDTO{}}
	for _, r := range s.Rejected {
		out.Rejected = append(out.Rejected, RejectedDTO{r.Key, r.ID, r.Code, r.Error, r.RuleIDs})
	}
	return out
}

type HealthDTO struct {
	Status          string `json:"status"`
	RulesSynced     bool   `json:"rules_synced"`
	WhitelistSynced bool   `json:"whitelist_synced"`
}
type NodeDTO struct {
	BaseURL       string             `json:"base_url"`
	KeyUnreadable bool               `json:"key_unreadable"`
	Overload      []OverloadDTO      `json:"overload"`
	Name          string             `json:"name"`
	Online        bool               `json:"online"`
	Incompatible  bool               `json:"incompatible"`
	Rules         SideDTO            `json:"rules"`
	Whitelist     SideDTO            `json:"whitelist"`
	HealthAt      string             `json:"health_at"`
	Health        HealthDTO          `json:"health"`
	StatsAt       string             `json:"stats_at"`
	Stats         map[string]any     `json:"stats"`
	Rates         map[string]float64 `json:"rates"`
}

func nodeDTO(n orch.NodeStatus) NodeDTO {
	return NodeDTO{"", false, overloadDTO(n.Overload), n.Name, n.Online, n.Incompatible, sideDTO(n.Rules), sideDTO(n.Whitelist), stamp(n.HealthAt), HealthDTO{n.Health.Status, n.Health.RulesSynced, n.Health.WhitelistSynced}, stamp(n.StatsAt), n.Stats, n.Rates}
}
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

type NodeSummary struct {
	Name         string `json:"name"`
	Online       bool   `json:"online"`
	Incompatible bool   `json:"incompatible"`
	RulesState   string `json:"rules_state"`
}
type CreateResponse struct {
	RuleDTO
	Existing bool          `json:"existing"`
	Gen      uint64        `json:"gen"`
	Epoch    string        `json:"epoch"`
	Nodes    []NodeSummary `json:"nodes"`
}
type BatchItem struct {
	Index    int      `json:"index"`
	Rule     *RuleDTO `json:"rule,omitempty"`
	Existing *bool    `json:"existing,omitempty"`
	Gen      *uint64  `json:"gen,omitempty"`
	Error    *Error   `json:"error,omitempty"`
}
type BatchResponse struct {
	Epoch   string      `json:"epoch"`
	Results []BatchItem `json:"results"`
}
type Page[T any] struct {
	Items     []T `json:"items"`
	NextAfter any `json:"next_after"`
}
type DeliveryDTO struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}
type DeliveryResponse struct {
	RuleID    string        `json:"rule_id"`
	Gen       uint64        `json:"gen"`
	TargetGen uint64        `json:"target_gen"`
	Epoch     string        `json:"epoch"`
	Nodes     []DeliveryDTO `json:"nodes"`
}

// DeliveryStatus supplies only delivery inputs; Service calls it while locked.
func DeliveryStatus(nodes Nodes) func() []rules.DeliveryNode {
	return func() []rules.DeliveryNode {
		out := []rules.DeliveryNode{}
		for _, n := range nodes.Status() {
			d := rules.DeliveryNode{Overloaded: len(n.Overload) > 0, Name: n.Name, Online: n.Online, Incompatible: n.Incompatible, Confirmable: n.Rules.Confirmable, Synced: n.Health.RulesSynced, ConfirmedGen: n.Rules.ConfirmedGen}
			for _, r := range n.Rules.Rejected {
				d.Rejected = append(d.Rejected, rules.DeliveryRejection{Key: r.Key, ID: r.ID, Code: r.Code, Error: r.Error, RuleIDs: r.RuleIDs})
			}
			out = append(out, d)
		}
		return out
	}
}
func deliveryState(r store.Rule, threshold uint64, n rules.DeliveryNode) DeliveryDTO {
	d := DeliveryDTO{Name: n.Name, State: "pending"}
	switch {
	case !r.Enabled:
		d.State = "disabled"
	case !n.Online:
		d.State = "offline"
	case n.Incompatible:
		d.State = "incompatible"
	case n.Overloaded:
		d.State = "overloaded"
	case !n.Confirmable || !n.Synced:
		return d
	default:
		for _, reject := range n.Rejected {
			match := reject.Key == r.GroupKey || reject.ID == r.ID
			for _, id := range reject.RuleIDs {
				match = match || id == r.ID
			}
			if match {
				d.State, d.Code, d.Error = "rejected", reject.Code, reject.Error
				return d
			}
		}
		if n.ConfirmedGen >= threshold {
			d.State = "confirmed"
		}
	}
	return d
}

type OverloadDTO struct {
	Dim   string `json:"dim"`
	Limit int    `json:"limit"`
	Used  int    `json:"used"`
}

func overloadDTO(dims []rules.Overload) []OverloadDTO {
	out := []OverloadDTO{}
	for _, d := range dims {
		out = append(out, OverloadDTO{d.Dim, d.Limit, d.Used})
	}
	return out
}

type TightestDTO struct {
	Name        string   `json:"name"`
	LimitSource string   `json:"limit_source"`
	Free        int      `json:"free"`
	Ratio       *float64 `json:"ratio"`
	Exhausted   bool     `json:"exhausted"`
}
type DimensionDTO struct {
	TightestDTO
	Used           int `json:"used"`
	Limit          int `json:"limit"`
	AdmissionLimit int `json:"admission_limit"`
}
type CapacityUsedDTO struct {
	Name  string `json:"name"`
	Limit int    `json:"limit"`
	Used  int    `json:"used"`
}
type OverloadedNodeDTO struct {
	Name string            `json:"name"`
	Dims []CapacityUsedDTO `json:"dims"`
}
type CapacityDTO struct {
	Dimensions []DimensionDTO `json:"dimensions"`
	Tightest   TightestDTO    `json:"tightest"`
	Candidates struct {
		Limit    int `json:"limit"`
		FullKeys int `json:"full_keys"`
		NearKeys int `json:"near_keys"`
	} `json:"candidates"`
	Rules struct {
		Enabled int `json:"enabled"`
		Total   int `json:"total"`
	} `json:"rules"`
	OverloadedNodes []OverloadedNodeDTO `json:"overloaded_nodes"`
}
type ReconcileDTO struct {
	LastAt    string `json:"last_at"`
	Result    string `json:"result"`
	Extra     int    `json:"extra"`
	Missing   int    `json:"missing"`
	Different int    `json:"different"`
}

func reconcileDTO(r orch.ReconcileStatus) ReconcileDTO {
	return ReconcileDTO{stamp(r.LastAt), r.Result, r.Diff.Extra, r.Diff.Missing, r.Diff.Different}
}

type CapacityComparisonDTO struct {
	Name           string `json:"name"`
	Limit          any    `json:"limit"`
	NodeUsed       any    `json:"node_used"`
	ControllerUsed int    `json:"controller_used"`
}
type SystemNodeDTO struct {
	NodeSummary
	Overloaded         bool                    `json:"overloaded"`
	WhitelistState     string                  `json:"whitelist_state"`
	StatsAt            string                  `json:"stats_at"`
	HostUptimeSeconds  any                     `json:"host_uptime_seconds"`
	CPUPercent         any                     `json:"cpu_percent"`
	MemPercent         any                     `json:"mem_percent"`
	LoadAvg1           any                     `json:"load_avg_1"`
	LoadAvg5           any                     `json:"load_avg_5"`
	LoadAvg15          any                     `json:"load_avg_15"`
	Counters           map[string]any          `json:"counters"`
	Rates              map[string]float64      `json:"rates"`
	AgentState         any                     `json:"agent_state"`
	Capacity           []CapacityComparisonDTO `json:"capacity"`
	RuleReconcile      ReconcileDTO            `json:"rule_reconcile"`
	WhitelistReconcile ReconcileDTO            `json:"whitelist_reconcile"`
}
type SystemDTO struct {
	Controller struct {
		StartedAt     string  `json:"started_at"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		DBBytes       int64   `json:"db_bytes"`
		RulesEnabled  int     `json:"rules_enabled"`
		RulesTotal    int     `json:"rules_total"`
		Whitelist     int     `json:"whitelist"`
		GoMem         struct {
			AllocBytes uint64 `json:"alloc_bytes"`
			SysBytes   uint64 `json:"sys_bytes"`
		} `json:"go_mem"`
	} `json:"controller"`
	Nodes []SystemNodeDTO `json:"nodes"`
}
