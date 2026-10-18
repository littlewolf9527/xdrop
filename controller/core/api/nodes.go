package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type nodesResponse struct {
	Epoch string    `json:"epoch"`
	Nodes []NodeDTO `json:"nodes"`
}

func (a *API) nodesData(status []orch.NodeStatus) (nodesResponse, *Error) {
	out := nodesResponse{a.service.Epoch(), []NodeDTO{}}
	seen := map[string]int{}
	for _, n := range status {
		seen[n.Name] = len(out.Nodes)
		out.Nodes = append(out.Nodes, nodeDTO(n))
	}
	if s := a.systemOptions.NodeStore; s != nil {
		rows, err := store.Nodes(s.DB.Reader())
		if err != nil {
			return out, &Error{Code: "internal"}
		}
		for _, row := range rows {
			_, err := s.Key.Open(row.Name, row.KeyNonce, row.KeyCipher)
			i, ok := seen[row.Name]
			if !ok {
				i = len(out.Nodes)
				seen[row.Name] = i
				out.Nodes = append(out.Nodes, NodeDTO{Name: row.Name})
			}
			out.Nodes[i].BaseURL, out.Nodes[i].KeyUnreadable = row.BaseURL, err != nil
		}
	}
	return out, nil
}

type NodePatch struct {
	BaseURL *string `json:"base_url"`
	APIKey  *string `json:"api_key"`
}
type NodeService struct {
	DB          *store.DB
	Key         *secret.Key
	Now         func() time.Time
	client      nc.Options
	afterCommit func()
}

func NewNodeService(db *store.DB, key *secret.Key) *NodeService {
	return &NodeService{DB: db, Key: key, Now: time.Now}
}
func nodeError(code, message string) *rules.Error {
	return &rules.Error{Code: code, Message: message}
}
func nodeView(n store.Node, changed bool) json.RawMessage {
	b, _ := json.Marshal(struct {
		Name       string `json:"name"`
		BaseURL    string `json:"base_url"`
		KeyChanged bool   `json:"key_changed"`
	}{n.Name, n.BaseURL, changed})
	return b
}

// Change commits the node and its audit together; callers serialize live updates.
func (s *NodeService) Change(who rules.Actor, operation, name string, in NodePatch) (spec nc.NodeSpec, failure *rules.Error) {
	internal := nodeError("internal", "node database operation failed")
	if strings.TrimSpace(name) == "" {
		return spec, nodeError("invalid_field", "name must not be empty")
	}
	if strings.Contains(name, "/") {
		return spec, nodeError("invalid_field", "name must not contain '/'")
	}
	if operation != "create" && operation != "update" && operation != "delete" {
		return spec, nodeError("bad_request", "invalid node operation")
	}
	if operation != "delete" && (operation == "create" && (in.BaseURL == nil || in.APIKey == nil) || in.BaseURL == nil && in.APIKey == nil) {
		return spec, nodeError("invalid_field", "node fields required")
	}
	if in.APIKey != nil && (len(*in.APIKey) == 0 || len(*in.APIKey) > 4096) {
		return spec, nodeError("invalid_field", "api_key must contain 1..4096 bytes")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return spec, internal
	}
	defer tx.Rollback()
	old, err := store.FindNode(tx, name)
	if err != nil && err != sql.ErrNoRows {
		return spec, internal
	}
	if operation == "create" && err == nil {
		return spec, nodeError("rule_conflict", "node already exists")
	}
	if operation != "create" && err == sql.ErrNoRows {
		return spec, nodeError("node_not_found", "node not found")
	}
	n := old
	n.Name, n.UpdatedAt, n.UpdatedBy = name, s.Now().UTC().Format(store.TimeFormat), who.Who()
	event := store.AuditEvent{At: n.UpdatedAt, Actor: who.Who(), Source: who.Source, Action: "node." + operation, Target: "node:" + name}
	if operation != "create" {
		event.Before = nodeView(old, false)
	} else {
		n.CreatedAt, n.CreatedBy = n.UpdatedAt, n.UpdatedBy
	}
	if operation == "delete" {
		err = store.DeleteNode(tx, name)
	} else {
		if in.BaseURL != nil {
			n.BaseURL = *in.BaseURL
		}
		var plain string
		if in.APIKey != nil {
			plain = *in.APIKey
			n.KeyNonce, n.KeyCipher, err = s.Key.Seal(name, plain)
		} else {
			plain, err = s.Key.Open(name, n.KeyNonce, n.KeyCipher)
		}
		if err != nil {
			return spec, nodeError("invalid_field", "node key unreadable; supply api_key")
		}
		spec = nc.NodeSpec{Name: name, BaseURL: n.BaseURL, Key: nc.Secret(plain)}
		if _, err = nc.New(spec, s.client); err != nil {
			return spec, nodeError("invalid_field", "invalid node URL")
		}
		err = store.PutNode(tx, n, operation == "create")
		event.After = nodeView(n, in.APIKey != nil)
	}
	if err != nil {
		return spec, internal
	}
	if store.InsertAudit(tx, event) != nil {
		return spec, internal
	}
	if tx.Commit() != nil {
		return spec, internal
	}
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return spec, nil
}

func (a *API) writeNode(c *gin.Context) {
	s := a.systemOptions.NodeStore
	if s == nil {
		a.fail(c, &Error{Code: "internal"})
		return
	}
	name, in := c.Param("name"), NodePatch{}
	operation, status := "delete", 204
	switch c.Request.Method {
	case "POST":
		var create struct {
			Name string `json:"name"`
			NodePatch
		}
		if !a.decode(c, &create, requestBytes) {
			return
		}
		name, in, operation, status = create.Name, create.NodePatch, "create", 201
	case "PATCH":
		if !a.decode(c, &in, requestBytes) {
			return
		}
		operation, status = "update", 200
	}
	a.nodeWrite.Lock()
	defer a.nodeWrite.Unlock()
	defer func() {
		a.topMu.Lock()
		a.top = nil
		a.topMu.Unlock()
	}()
	spec, err := s.Change(actor(c), operation, name, in)
	if a.serviceError(c, err) {
		return
	}
	if operation != "create" {
		a.nodes.RemoveNode(name)
	}
	if operation != "delete" {
		if a.nodes.AddNode(spec) != nil {
			a.fail(c, &Error{Code: "internal"})
			return
		}
		c.JSON(status, struct {
			Name    string `json:"name"`
			BaseURL string `json:"base_url"`
		}{name, spec.BaseURL})
	} else {
		c.Status(status)
	}
}

type nodeTestDTO struct {
	Reachable   bool   `json:"reachable"`
	Compatible  bool   `json:"compatible"`
	KeyAccepted bool   `json:"key_accepted"`
	Message     string `json:"message"`
}

func testNode(ctx context.Context, client *nc.Client) nodeTestDTO {
	probe, err := client.Probe(ctx)
	out := nodeTestDTO{Reachable: probe != nc.Unreachable, Compatible: probe == nc.OK}
	if err != nil {
		out.Message = err.Message
		return out
	}
	_, err = client.Stats(ctx)
	out.KeyAccepted = err == nil
	if err != nil {
		out.Message = err.Message
	}
	return out
}
func (a *API) testNode(c *gin.Context) {
	s := a.systemOptions.NodeStore
	if s == nil {
		a.fail(c, &Error{Code: "internal"})
		return
	}
	var spec nc.NodeSpec
	if name := c.Param("name"); name != "" {
		a.nodeWrite.Lock()
		defer a.nodeWrite.Unlock()
		n, err := store.FindNode(s.DB.Reader(), name)
		if err == sql.ErrNoRows {
			a.fail(c, &Error{Code: "node_not_found"})
			return
		}
		if err != nil {
			a.fail(c, &Error{Code: "internal"})
			return
		}
		plain, err := s.Key.Open(name, n.KeyNonce, n.KeyCipher)
		if err != nil {
			c.JSON(200, nodeTestDTO{Message: "node key unreadable"})
			return
		}
		spec = nc.NodeSpec{Name: name, BaseURL: n.BaseURL, Key: nc.Secret(plain)}
	} else {
		var in NodePatch
		if !a.decode(c, &in, requestBytes) {
			return
		}
		if in.BaseURL == nil || in.APIKey == nil || len(*in.APIKey) == 0 || len(*in.APIKey) > 4096 {
			a.fail(c, &Error{Code: "invalid_field", Message: "base_url and api_key (1..4096 bytes) required"})
			return
		}
		spec = nc.NodeSpec{BaseURL: *in.BaseURL, Key: nc.Secret(*in.APIKey)}
	}
	client, err := nc.New(spec, s.client)
	if err != nil {
		a.fail(c, &Error{Code: "invalid_field", Message: "invalid node URL"})
		return
	}
	c.JSON(200, testNode(c.Request.Context(), client))
}
