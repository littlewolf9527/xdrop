// Package sync provides Controller synchronization functionality
package sync

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/littlewolf9527/xdrop/node/agent/api"
)

// SyncConfig configuration for Controller sync
type SyncConfig struct {
	ControllerURL string
	APIKey        string
	RetryCount    int
	RetryInterval time.Duration
	Timeout       time.Duration
}

// ControllerSync handles synchronization with Controller
type ControllerSync struct {
	config     SyncConfig
	httpClient *http.Client
}

// NewControllerSync creates a new ControllerSync
func NewControllerSync(config SyncConfig) *ControllerSync {
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = 5 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	return &ControllerSync{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// Rule represents a rule from Controller (matches Controller format)
type Rule struct {
	ID        string `json:"id"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	SrcCIDR   string `json:"src_cidr,omitempty"`
	DstCIDR   string `json:"dst_cidr,omitempty"`
	SrcPort   uint16 `json:"src_port,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Action    string `json:"action"`
	RateLimit uint32 `json:"rate_limit,omitempty"`
	PktLenMin uint16 `json:"pkt_len_min,omitempty"`
	PktLenMax uint16 `json:"pkt_len_max,omitempty"`
}

// WhitelistEntry represents a whitelist entry from Controller
type WhitelistEntry struct {
	ID       string `json:"id"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// FetchRules fetches all rules from Controller
func (s *ControllerSync) FetchRules() ([]Rule, error) {
	url := s.config.ControllerURL + "/api/v1/rules"

	req, _ := http.NewRequest("GET", url, nil)
	if s.config.APIKey != "" {
		req.Header.Set("X-API-Key", s.config.APIKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Rules []Rule `json:"rules"`
		Count int    `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode rules: %w", err)
	}

	return result.Rules, nil
}

// FetchWhitelist fetches all whitelist entries from Controller
func (s *ControllerSync) FetchWhitelist() ([]WhitelistEntry, error) {
	url := s.config.ControllerURL + "/api/v1/whitelist"

	req, _ := http.NewRequest("GET", url, nil)
	if s.config.APIKey != "" {
		req.Header.Set("X-API-Key", s.config.APIKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch whitelist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Entries []WhitelistEntry `json:"entries"`
		Count   int              `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode whitelist: %w", err)
	}

	return result.Entries, nil
}

// SyncOnStartup synchronizes rules and whitelist from Controller on startup
func (s *ControllerSync) SyncOnStartup(handlers *api.Handlers) error {
	log.Printf("[Sync] Connecting to Controller at %s...", s.config.ControllerURL)

	var lastErr error

	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			log.Printf("[Sync] Retry %d/%d in %v...", attempt, s.config.RetryCount, s.config.RetryInterval)
			time.Sleep(s.config.RetryInterval)
		}

		// Fetch and add rules
		rules, err := s.FetchRules()
		if err != nil {
			lastErr = err
			log.Printf("[Sync] Failed to fetch rules: %v", err)
			continue
		}

		// Fetch and add whitelist
		whitelist, err := s.FetchWhitelist()
		if err != nil {
			lastErr = err
			log.Printf("[Sync] Failed to fetch whitelist: %v", err)
			continue
		}

		// Step 1: Whitelist FIRST — must be fully armed before blacklist goes live.
		// Clear any residual whitelist state from previous failed attempts
		// to ensure each attempt starts from a clean slate.
		if err := handlers.ClearAllWhitelistFromSync(); err != nil {
			lastErr = fmt.Errorf("whitelist cleanup failed: %w", err)
			log.Printf("[Sync] Whitelist cleanup failed: %v — aborting attempt", err)
			continue
		}

		// If any whitelist entry fails, abort this attempt (fail-fast) to avoid
		// arming the blacklist with incomplete exemptions.
		wlAdded := 0
		wlFailed := false
		for _, entry := range whitelist {
			syncEntry := api.SyncWhitelistEntry{
				ID:       entry.ID,
				SrcIP:    entry.SrcIP,
				DstIP:    entry.DstIP,
				SrcPort:  entry.SrcPort,
				DstPort:  entry.DstPort,
				Protocol: entry.Protocol,
			}
			if err := handlers.AddWhitelistFromSync(syncEntry); err != nil {
				lastErr = fmt.Errorf("whitelist entry %s failed: %w", entry.ID, err)
				log.Printf("[Sync] Whitelist replay failed for %s: %v — aborting attempt", entry.ID, err)
				wlFailed = true
				break
			}
			wlAdded++
		}
		if wlFailed {
			continue // retry — do NOT proceed to DoAtomicSync with incomplete whitelist
		}
		log.Printf("[Sync] Whitelist replay complete: %d entries", wlAdded)

		// Step 2: Blacklist rules via AtomicSync — whitelist already in place.
		var apiRules []api.Rule
		for _, rule := range rules {
			apiRules = append(apiRules, api.Rule{
				ID:        rule.ID,
				SrcIP:     rule.SrcIP,
				DstIP:     rule.DstIP,
				SrcCIDR:   rule.SrcCIDR,
				DstCIDR:   rule.DstCIDR,
				SrcPort:   rule.SrcPort,
				DstPort:   rule.DstPort,
				Protocol:  rule.Protocol,
				Action:    rule.Action,
				RateLimit: rule.RateLimit,
				PktLenMin: rule.PktLenMin,
				PktLenMax: rule.PktLenMax,
			})
		}
		result, err := handlers.DoAtomicSync(apiRules)
		if err != nil {
			lastErr = err
			log.Printf("[Sync] AtomicSync failed: %v (added=%d, failed=%d)", err, result.Added, result.Failed)
			continue
		}
		rulesAdded := result.Added

		log.Printf("[Sync] Successfully synced from Controller: %d rules, %d whitelist entries", rulesAdded, wlAdded)
		return nil
	}

	// All retries exhausted — clean up any partial whitelist state from the last
	// failed attempt so the agent does not boot with inconsistent whitelist residue.
	//
	// Accepted risk: if ClearAllWhitelistFromSync() itself fails (BPF delete error),
	// we log a warning and continue rather than crashing. This is intentional:
	//   - DoAtomicSync() was never called, so no blacklist rules are active in BPF.
	//   - Whitelist residue without a blacklist is inert — it exempts traffic from a
	//     blacklist that does not exist, causing no dropped-traffic impact.
	//   - Crashing the agent here would leave the node completely unreachable,
	//     preventing the controller from pushing a corrective full-sync.
	//   - The controller's next FullSyncToNode will overwrite any stale state.
	if err := handlers.ClearAllWhitelistFromSync(); err != nil {
		log.Printf("[Sync] WARN: final whitelist cleanup failed: %v — agent will continue without blacklist rules; controller full-sync will correct state", err)
	}

	return fmt.Errorf("failed to sync from Controller after %d attempts: %w", s.config.RetryCount+1, lastErr)
}
