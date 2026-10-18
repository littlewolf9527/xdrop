package api

import (
	"errors"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

const (
	mutationInvalid   = "validation_rejected"
	mutationDifferent = "content_different"
)

// Compare normalized intent, including all three nullable-field states.
func sameExactContent(old StoredRule, key RuleKey, incoming Rule) bool {
	a, b := exactIntent(old), exactIntent(ruleToStored(key, incoming))
	return a.valid && b.valid && a == b
}
func sameCIDRContent(old StoredCIDRRule, src, dst string, srcPort, dstPort uint16, proto uint8, incoming Rule) bool {
	key := CIDRRuleKey{SrcID: old.Key.SrcID, DstID: old.Key.DstID, SrcPort: srcPort, DstPort: dstPort, Protocol: proto}
	a, b := cidrIntent(old), cidrIntent(ruleToStoredCIDR(key, src, dst, incoming))
	return a.valid && b.valid && a == b
}

// isMapEntryMissing reports whether a map Delete returned ENOENT, which
// happens when the key was never present. For lazily-populated maps such as
// rl_states (written on first match, not on rule insert), ENOENT is the common
// case for never-matched rules — not a real error.
//
// Post-migration: cilium/ebpf returns the typed sentinel ebpf.ErrKeyNotExist.
// The goebpf string-match path is kept as a belt-and-braces fallback for any
// transitional build that still links both libraries.
func isMapEntryMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	return strings.Contains(err.Error(), "No such file or directory")
}

// ruleJSON encodes every rule-write response under the current protocol.
func (h *Handlers) ruleJSON(c *gin.Context, status int, body gin.H) {
	c.JSON(status, body)
}
