// XDrop Agent - Whitelist CRUD handlers (Phase 8: 31-combo bitmap-gated dual-buffer)
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListWhitelist(c *gin.Context) {
	h.wlMu.RLock()
	defer h.wlMu.RUnlock()

	entries := make([]WhitelistEntry, 0, len(h.wlEntries))
	for id, key := range h.wlEntries {
		entries = append(entries, h.keyToWhitelist(id, key))
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"count":   len(entries),
	})
}
