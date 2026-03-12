package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// WhitelistHandler handles whitelist API requests.
type WhitelistHandler struct {
	svc *service.WhitelistService
}

// NewWhitelistHandler creates a new WhitelistHandler.
func NewWhitelistHandler(svc *service.WhitelistService) *WhitelistHandler {
	return &WhitelistHandler{svc: svc}
}

// List returns all whitelist entries.
func (h *WhitelistHandler) List(c *gin.Context) {
	entries, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"count":   len(entries),
	})
}

// Create adds a new whitelist entry.
func (h *WhitelistHandler) Create(c *gin.Context) {
	var req model.WhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	entry, sr, err := h.svc.Create(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"entry":   entry,
	}, sr))
}

// Delete removes a whitelist entry by ID.
func (h *WhitelistHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	sr, err := h.svc.Delete(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"message": "Whitelist entry deleted",
	}, sr))
}
