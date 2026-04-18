package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NodeClient is the HTTP client for the node API
type NodeClient struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewNodeClient creates a new node API client
func NewNodeClient(timeout time.Duration) *NodeClient {
	return &NodeClient{
		httpClient: &http.Client{Timeout: timeout},
		timeout:    timeout,
	}
}

// Response is the generic API response
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
	ID      string `json:"id,omitempty"`
	Added   int    `json:"added,omitempty"`
	Failed  int    `json:"failed,omitempty"`
	Deleted int    `json:"deleted,omitempty"`
}

// Ping checks node health using the authenticated stats endpoint.
// This ensures that a misconfigured API key is detected as unhealthy.
func (c *NodeClient) Ping(endpoint, apiKey string) error {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/stats", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned status %d", resp.StatusCode)
	}
	return nil
}

// GetStats retrieves node statistics
func (c *NodeClient) GetStats(endpoint, apiKey string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/stats", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node returned status %d", resp.StatusCode)
	}

	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}
	return stats, nil
}

// RuleStats holds per-rule traffic counters
type RuleStats struct {
	MatchCount uint64  `json:"match_count"`
	DropCount  uint64  `json:"drop_count"`
	DropPPS    float64 `json:"drop_pps"`
}

// NodeRule is a rule entry returned by the node (with optional stats)
type NodeRule struct {
	ID    string     `json:"id"`
	Stats *RuleStats `json:"stats,omitempty"`
}

// NodeRulesResponse is the node rules list response
type NodeRulesResponse struct {
	Rules []NodeRule `json:"rules"`
	Count int        `json:"count"`
}

// GetRulesWithStats retrieves the node rule list with traffic statistics
func (c *NodeClient) GetRulesWithStats(endpoint, apiKey string) (*NodeRulesResponse, error) {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/rules", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result NodeRulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AddRule adds a rule to the node
func (c *NodeClient) AddRule(endpoint, apiKey string, rule map[string]interface{}) (*Response, error) {
	return c.post(endpoint+"/api/v1/rules", apiKey, rule)
}

// DeleteRule removes a rule from the node
func (c *NodeClient) DeleteRule(endpoint, apiKey, ruleID string) (*Response, error) {
	return c.delete(endpoint+"/api/v1/rules/"+ruleID, apiKey)
}

// AddRulesBatch adds rules in batch to the node
func (c *NodeClient) AddRulesBatch(endpoint, apiKey string, rules []map[string]interface{}) (*Response, error) {
	return c.post(endpoint+"/api/v1/rules/batch", apiKey, map[string]interface{}{"rules": rules})
}

// DeleteRulesBatch deletes rules in batch from the node
func (c *NodeClient) DeleteRulesBatch(endpoint, apiKey string, ids []string) (*Response, error) {
	return c.doDelete(endpoint+"/api/v1/rules/batch", apiKey, map[string]interface{}{"ids": ids})
}

// AddWhitelist adds a whitelist entry to the node
func (c *NodeClient) AddWhitelist(endpoint, apiKey string, entry map[string]interface{}) (*Response, error) {
	return c.post(endpoint+"/api/v1/whitelist", apiKey, entry)
}

// DeleteWhitelist removes a whitelist entry from the node
func (c *NodeClient) DeleteWhitelist(endpoint, apiKey, id string) (*Response, error) {
	return c.delete(endpoint+"/api/v1/whitelist/"+id, apiKey)
}

// AddWhitelistBatch adds whitelist entries in batch to the node
func (c *NodeClient) AddWhitelistBatch(endpoint, apiKey string, entries []map[string]interface{}) (*Response, error) {
	return c.post(endpoint+"/api/v1/whitelist/batch", apiKey, map[string]interface{}{"entries": entries})
}

// DeleteWhitelistBatch deletes whitelist entries in batch from the node
func (c *NodeClient) DeleteWhitelistBatch(endpoint, apiKey string, ids []string) (*Response, error) {
	return c.doDelete(endpoint+"/api/v1/whitelist/batch", apiKey, map[string]interface{}{"ids": ids})
}

// WhitelistResponse is the node whitelist list response
type WhitelistResponse struct {
	Entries []struct {
		ID string `json:"id"`
	} `json:"entries"`
}

// GetWhitelist retrieves the node whitelist
func (c *NodeClient) GetWhitelist(endpoint, apiKey string) (*WhitelistResponse, error) {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/whitelist", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /whitelist returned HTTP %d", resp.StatusCode)
	}

	var result WhitelistResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRuleIDs retrieves the list of rule IDs from the node
func (c *NodeClient) GetRuleIDs(endpoint, apiKey string) ([]string, error) {
	rulesResp, err := c.GetRulesWithStats(endpoint, apiKey)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rulesResp.Rules))
	for _, r := range rulesResp.Rules {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// GetWhitelistIDs retrieves the list of whitelist entry IDs from the node
func (c *NodeClient) GetWhitelistIDs(endpoint, apiKey string) ([]string, error) {
	wlResp, err := c.GetWhitelist(endpoint, apiKey)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(wlResp.Entries))
	for _, e := range wlResp.Entries {
		ids = append(ids, e.ID)
	}
	return ids, nil
}

// GetRulesRaw retrieves the node's current rule list as raw maps, suitable
// for use as a rollback snapshot. Read-only fields (stats) are stripped.
func (c *NodeClient) GetRulesRaw(endpoint, apiKey string) ([]map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/rules", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /rules returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	for _, r := range envelope.Rules {
		delete(r, "stats")
	}
	return envelope.Rules, nil
}

// GetWhitelistRaw retrieves the node's current whitelist as raw maps, suitable
// for use as a rollback snapshot.
func (c *NodeClient) GetWhitelistRaw(endpoint, apiKey string) ([]map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", endpoint+"/api/v1/whitelist", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /whitelist returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return envelope.Entries, nil
}

// AtomicSync calls the node's atomic sync API (blacklist rules only, excludes whitelist)
func (c *NodeClient) AtomicSync(endpoint, apiKey string, rules []map[string]interface{}) (*Response, error) {
	return c.post(endpoint+"/api/v1/sync/atomic", apiKey, map[string]interface{}{
		"rules": rules,
	})
}

// FullSync fully synchronizes rules and whitelist to the node.
//
// This is the fallback path for old nodes without /sync/atomic. It snapshots
// the node's current state before deletion so it can best-effort restore on
// add failure, eliminating the "delete succeeded, add failed → node has 0
// rules" failure mode called out in BUG-047.
//
// Rollback semantics:
//   - Delete fails before state mutation → return error, node unchanged.
//   - Delete succeeds, Add fails → attempt to re-insert the snapshot (best
//     effort). If re-insert also fails, return a combined error so the caller
//     can surface that the node is in an uncertain state.
//   - Whitelist has the same pattern.
func (c *NodeClient) FullSync(endpoint, apiKey string, rules []map[string]interface{}, whitelist []map[string]interface{}) error {
	// === Sync rules ===
	ruleSnapshot, err := c.GetRulesRaw(endpoint, apiKey)
	if err != nil {
		return fmt.Errorf("failed to snapshot existing rules: %w", err)
	}

	// Delete existing rules. Like the batch-add path, the node reports failure
	// in two ways: transport error OR HTTP 200 with resp.Failed > 0. Partial
	// delete must abort the sync — otherwise old rules survive into the new
	// apply and the node ends in a mixed state (AUD-V242-002).
	if len(ruleSnapshot) > 0 {
		ruleIDs := make([]string, 0, len(ruleSnapshot))
		for _, r := range ruleSnapshot {
			if id, ok := r["id"].(string); ok {
				ruleIDs = append(ruleIDs, id)
			}
		}
		resp, err := c.DeleteRulesBatch(endpoint, apiKey, ruleIDs)
		if err != nil {
			return fmt.Errorf("failed to delete existing rules: %w", err)
		}
		if resp != nil && resp.Failed > 0 {
			return fmt.Errorf("partial delete: %d/%d existing rules could not be removed; aborting sync", resp.Failed, len(ruleIDs))
		}
	}

	// Add new rules in batch; rollback to snapshot on failure.
	// The node's batch API signals failure in two ways:
	//   (a) transport/HTTP error → err != nil
	//   (b) business-level rejection → HTTP 200 with resp.Failed > 0
	// Both must trigger rollback. See AUD-V242-001.
	if len(rules) > 0 {
		resp, err := c.AddRulesBatch(endpoint, apiKey, rules)
		addFailed := err != nil || (resp != nil && resp.Failed > 0)
		if addFailed {
			primaryErr := err
			if primaryErr == nil {
				primaryErr = fmt.Errorf("partial add: %d/%d rules rejected by node", resp.Failed, len(rules))
			}
			if len(ruleSnapshot) == 0 {
				return primaryErr
			}
			// Before re-inserting the snapshot, clear out any rules the partial
			// primary add managed to install, so the rolled-back state is the
			// snapshot and not snapshot∪partial-accept. Partial pre-clean is
			// treated as a failure too (AUD-V242-002) — a residue leak would
			// recreate the exact class of mixed-state bug this path is fixing.
			if currentIDs, gErr := c.GetRuleIDs(endpoint, apiKey); gErr == nil && len(currentIDs) > 0 {
				dResp, dErr := c.DeleteRulesBatch(endpoint, apiKey, currentIDs)
				switch {
				case dErr != nil:
					return fmt.Errorf("add rules failed (%w); rollback pre-clean also failed: %v", primaryErr, dErr)
				case dResp != nil && dResp.Failed > 0:
					return fmt.Errorf("add rules failed (%w); rollback pre-clean partially failed: only %d/%d residue rules removed", primaryErr, dResp.Deleted, len(currentIDs))
				}
			}
			rResp, rErr := c.AddRulesBatch(endpoint, apiKey, ruleSnapshot)
			switch {
			case rErr != nil:
				return fmt.Errorf("add rules failed (%w); rollback to snapshot also failed: %v", primaryErr, rErr)
			case rResp != nil && rResp.Failed > 0:
				return fmt.Errorf("add rules failed (%w); rollback partially failed: only %d/%d snapshot rules restored", primaryErr, rResp.Added, len(ruleSnapshot))
			default:
				return fmt.Errorf("add rules failed, rolled back to snapshot of %d rules: %w", len(ruleSnapshot), primaryErr)
			}
		}
	}

	// === Sync whitelist (using batch API) ===
	wlSnapshot, err := c.GetWhitelistRaw(endpoint, apiKey)
	if err != nil {
		return fmt.Errorf("failed to snapshot existing whitelist: %w", err)
	}

	// Delete existing whitelist entries in batch. Same dual-failure contract
	// as the rules delete path (AUD-V242-002): transport error OR HTTP 200
	// with resp.Failed > 0 both abort the sync.
	if len(wlSnapshot) > 0 {
		wlIDs := make([]string, 0, len(wlSnapshot))
		for _, w := range wlSnapshot {
			if id, ok := w["id"].(string); ok {
				wlIDs = append(wlIDs, id)
			}
		}
		resp, err := c.DeleteWhitelistBatch(endpoint, apiKey, wlIDs)
		if err != nil {
			return fmt.Errorf("failed to delete existing whitelist: %w", err)
		}
		if resp != nil && resp.Failed > 0 {
			return fmt.Errorf("partial delete: %d/%d existing whitelist entries could not be removed; aborting sync", resp.Failed, len(wlIDs))
		}
	}

	// Add new whitelist entries in batch; rollback to snapshot on failure.
	// Same dual-failure model as the rules path (AUD-V242-001):
	// transport error OR HTTP 200 with resp.Failed > 0 both trigger rollback.
	if len(whitelist) > 0 {
		resp, err := c.AddWhitelistBatch(endpoint, apiKey, whitelist)
		addFailed := err != nil || (resp != nil && resp.Failed > 0)
		if addFailed {
			primaryErr := err
			if primaryErr == nil {
				primaryErr = fmt.Errorf("partial add: %d/%d whitelist entries rejected by node", resp.Failed, len(whitelist))
			}
			if len(wlSnapshot) == 0 {
				return fmt.Errorf("failed to add whitelist batch: %w", primaryErr)
			}
			// Pre-clean any partial-add residue before restoring the snapshot.
			// Partial pre-clean also counts as a rollback failure (AUD-V242-002).
			if currentIDs, gErr := c.GetWhitelistIDs(endpoint, apiKey); gErr == nil && len(currentIDs) > 0 {
				dResp, dErr := c.DeleteWhitelistBatch(endpoint, apiKey, currentIDs)
				switch {
				case dErr != nil:
					return fmt.Errorf("add whitelist failed (%w); rollback pre-clean also failed: %v", primaryErr, dErr)
				case dResp != nil && dResp.Failed > 0:
					return fmt.Errorf("add whitelist failed (%w); rollback pre-clean partially failed: only %d/%d residue entries removed", primaryErr, dResp.Deleted, len(currentIDs))
				}
			}
			rResp, rErr := c.AddWhitelistBatch(endpoint, apiKey, wlSnapshot)
			switch {
			case rErr != nil:
				return fmt.Errorf("add whitelist failed (%w); rollback to snapshot also failed: %v", primaryErr, rErr)
			case rResp != nil && rResp.Failed > 0:
				return fmt.Errorf("add whitelist failed (%w); rollback partially failed: only %d/%d snapshot entries restored", primaryErr, rResp.Added, len(wlSnapshot))
			default:
				return fmt.Errorf("add whitelist failed, rolled back to snapshot of %d entries: %w", len(wlSnapshot), primaryErr)
			}
		}
	}

	return nil
}

// DiffSync incrementally synchronizes rules and whitelist to the node.
// Computes toAdd/toDelete from ID set differences; execution order: DELETE then ADD.
func (c *NodeClient) DiffSync(endpoint, apiKey string,
	targetRules []map[string]interface{},
	targetWhitelist []map[string]interface{},
) error {
	// === Rules diff ===
	targetRuleMap := make(map[string]map[string]interface{}, len(targetRules))
	for _, r := range targetRules {
		if id, ok := r["id"].(string); ok {
			targetRuleMap[id] = r
		}
	}

	nodeRuleIDs, err := c.GetRuleIDs(endpoint, apiKey)
	if err != nil {
		return fmt.Errorf("diff sync: failed to get node rule IDs: %w", err)
	}

	nodeRuleSet := make(map[string]bool, len(nodeRuleIDs))
	for _, id := range nodeRuleIDs {
		nodeRuleSet[id] = true
	}

	var rulesToDelete []string
	for _, id := range nodeRuleIDs {
		if _, exists := targetRuleMap[id]; !exists {
			rulesToDelete = append(rulesToDelete, id)
		}
	}

	var rulesToAdd []map[string]interface{}
	for id, rule := range targetRuleMap {
		if !nodeRuleSet[id] {
			rulesToAdd = append(rulesToAdd, rule)
		}
	}

	// Execute: DELETE first, then ADD (avoid CIDR overlap / duplicate key conflicts)
	if len(rulesToDelete) > 0 {
		for i := 0; i < len(rulesToDelete); i += 1000 {
			end := i + 1000
			if end > len(rulesToDelete) {
				end = len(rulesToDelete)
			}
			if _, err := c.DeleteRulesBatch(endpoint, apiKey, rulesToDelete[i:end]); err != nil {
				return fmt.Errorf("diff sync: failed to delete rules batch: %w", err)
			}
		}
	}

	if len(rulesToAdd) > 0 {
		for i := 0; i < len(rulesToAdd); i += 1000 {
			end := i + 1000
			if end > len(rulesToAdd) {
				end = len(rulesToAdd)
			}
			if _, err := c.AddRulesBatch(endpoint, apiKey, rulesToAdd[i:end]); err != nil {
				return fmt.Errorf("diff sync: failed to add rules batch: %w", err)
			}
		}
	}

	// === Whitelist diff ===
	targetWlMap := make(map[string]map[string]interface{}, len(targetWhitelist))
	for _, w := range targetWhitelist {
		if id, ok := w["id"].(string); ok {
			targetWlMap[id] = w
		}
	}

	nodeWlIDs, err := c.GetWhitelistIDs(endpoint, apiKey)
	if err != nil {
		return fmt.Errorf("diff sync: failed to get node whitelist IDs: %w", err)
	}

	nodeWlSet := make(map[string]bool, len(nodeWlIDs))
	for _, id := range nodeWlIDs {
		nodeWlSet[id] = true
	}

	var wlToDelete []string
	for _, id := range nodeWlIDs {
		if _, exists := targetWlMap[id]; !exists {
			wlToDelete = append(wlToDelete, id)
		}
	}

	var wlToAdd []map[string]interface{}
	for id, entry := range targetWlMap {
		if !nodeWlSet[id] {
			wlToAdd = append(wlToAdd, entry)
		}
	}

	// Execute whitelist diff: DELETE → ADD
	if len(wlToDelete) > 0 {
		for i := 0; i < len(wlToDelete); i += 1000 {
			end := i + 1000
			if end > len(wlToDelete) {
				end = len(wlToDelete)
			}
			if _, err := c.DeleteWhitelistBatch(endpoint, apiKey, wlToDelete[i:end]); err != nil {
				return fmt.Errorf("diff sync: failed to delete whitelist batch: %w", err)
			}
		}
	}

	if len(wlToAdd) > 0 {
		for i := 0; i < len(wlToAdd); i += 1000 {
			end := i + 1000
			if end > len(wlToAdd) {
				end = len(wlToAdd)
			}
			if _, err := c.AddWhitelistBatch(endpoint, apiKey, wlToAdd[i:end]); err != nil {
				return fmt.Errorf("diff sync: failed to add whitelist batch: %w", err)
			}
		}
	}

	return nil
}

func (c *NodeClient) post(url, apiKey string, data interface{}) (*Response, error) {
	body, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var r Response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &r, nil
}

func (c *NodeClient) delete(url, apiKey string) (*Response, error) {
	req, _ := http.NewRequest("DELETE", url, nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var r Response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &r, nil
}

func (c *NodeClient) doDelete(url, apiKey string, data interface{}) (*Response, error) {
	body, _ := json.Marshal(data)
	req, _ := http.NewRequest("DELETE", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var r Response
	if err := json.Unmarshal(bodyBytes, &r); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &r, nil
}
