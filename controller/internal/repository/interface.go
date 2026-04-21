package repository

import (
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// PaginationParams holds parameters for a paginated query
type PaginationParams struct {
	Page    int
	Limit   int
	Sort    string // "created_at" | "updated_at"
	Order   string // "asc" | "desc"
	Search  string
	Enabled *bool
	Action  string
}

// PaginationResult holds pagination metadata for a query result
type PaginationResult struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Total int `json:"total"`
	Pages int `json:"pages"`
}

// RuleRepository is the interface for rule storage
type RuleRepository interface {
	Create(rule *model.Rule) error
	BatchCreate(rules []*model.Rule) error
	Get(id string) (*model.Rule, error)
	List() ([]*model.Rule, error)
	ListPaginated(params PaginationParams) ([]*model.Rule, *PaginationResult, error)
	ListEnabled() ([]*model.Rule, error)
	ListExpired() ([]*model.Rule, error)
	Update(rule *model.Rule) error
	Delete(id string) error
	BatchDelete(ids []string) error
	DeleteExpired() (int, error)
	Exists(srcIP, dstIP string, srcPort, dstPort int, protocol string) (bool, error)
	CIDRExists(srcCIDR, dstCIDR string, srcPort, dstPort int, protocol string) (bool, error)
	// GetByTuple / GetByCIDRTuple return the rule matching the given 5-tuple
	// (exact IP or CIDR respectively), or (nil, nil) when none exists.
	// Used by v2.6.1 anomaly merge path (proposal §7.2.1).
	GetByTuple(srcIP, dstIP string, srcPort, dstPort int, protocol string) (*model.Rule, error)
	GetByCIDRTuple(srcCIDR, dstCIDR string, srcPort, dstPort int, protocol string) (*model.Rule, error)
	ListSrcCIDRs() ([]string, error)
	ListDstCIDRs() ([]string, error)
}

// WhitelistRepository is the interface for whitelist storage
type WhitelistRepository interface {
	Create(entry *model.Whitelist) error
	Get(id string) (*model.Whitelist, error)
	List() ([]*model.Whitelist, error)
	Delete(id string) error
}

// NodeRepository is the interface for node storage
type NodeRepository interface {
	Create(node *model.Node) error
	Get(id string) (*model.Node, error)
	GetByEndpoint(endpoint string) (*model.Node, error)
	List() ([]*model.Node, error)
	Update(node *model.Node) error
	Delete(id string) error
	UpdateStatus(id string, status string) error
	UpdateLastSeen(id string) error
	UpdateLastSync(id string) error
}

// SyncLogRepository is the interface for sync log storage
type SyncLogRepository interface {
	Log(nodeID, action, ruleID, status, errMsg string) error
	ListByNode(nodeID string, limit int) ([]SyncLogEntry, error)
}

// SyncLogEntry represents a single sync log record
type SyncLogEntry struct {
	ID        int64  `json:"id"`
	NodeID    string `json:"node_id"`
	Action    string `json:"action"`
	RuleID    string `json:"rule_id,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	CreatedAt string `json:"created_at"`
}
