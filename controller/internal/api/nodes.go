package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// NodesHandler handles node API requests.
type NodesHandler struct {
	svc *service.NodeService
}

// NewNodesHandler creates a new NodesHandler.
func NewNodesHandler(svc *service.NodeService) *NodesHandler {
	return &NodesHandler{svc: svc}
}

// List returns all nodes.
func (h *NodesHandler) List(c *gin.Context) {
	nodes, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes": nodes,
		"count": len(nodes),
	})
}

// Get retrieves node details.
func (h *NodesHandler) Get(c *gin.Context) {
	id := c.Param("id")
	node, err := h.svc.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}

	c.JSON(http.StatusOK, node)
}

// Register registers a new node.
func (h *NodesHandler) Register(c *gin.Context) {
	var req model.NodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	node, err := h.svc.Register(&req)
	if err != nil {
		if errors.Is(err, service.ErrNodeReadOnly) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"node":    node,
	})
}

// Delete removes a node.
func (h *NodesHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Delete(id); err != nil {
		if errors.Is(err, service.ErrNodeReadOnly) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Node deleted",
	})
}

// Update modifies a node (name, API key, etc.).
func (h *NodesHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name   string `json:"name"`
		ApiKey string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	node, err := h.svc.Update(id, req.Name, req.ApiKey)
	if err != nil {
		if errors.Is(err, service.ErrNodeReadOnly) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"node":    node,
	})
}

// GetStats retrieves statistics for a node.
func (h *NodesHandler) GetStats(c *gin.Context) {
	id := c.Param("id")
	stats, err := h.svc.GetStats(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ForceSync triggers an immediate full sync for a node.
func (h *NodesHandler) ForceSync(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.ForceSync(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sync initiated",
	})
}
