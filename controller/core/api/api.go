// Package api exposes the controller contract under /api/v1.
package api

import (
	"fmt"
	"github.com/littlewolf9527/xdrop/controller/core/condexpr"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type Authenticator func(*http.Request) (rules.Actor, *Error)

type Nodes interface {
	Status() []orch.NodeStatus
	ForceSync(string)
	ReconcileNow(string)
	AddNode(nc.NodeSpec) error
	RemoveNode(string)
}

const (
	batchLimit   = 500
	pageMax      = 1000
	pageDefault  = 100
	requestBytes = 1 << 20
	batchBytes   = 8 << 20
)

type Options struct {
	nodesRead                                                                func() *Error
	hub                                                                      *Hub
	eventsTick                                                               func(time.Duration) (<-chan time.Time, func())
	afterSnapshotRead, beforeWriteAuth, atRegister, afterRegister, roundDone func()
	trafficQuery                                                             store.Queryer
	Database                                                                 string
	StartedAt                                                                time.Time
	Accounts                                                                 *auth.Service
	NodeStore                                                                *NodeService
	nodeAPI                                                                  func(*API)
}
type API struct {
	topMu         sync.Mutex
	top           map[int]topMemo
	systemOptions Options
	service       *rules.Service
	nodes         Nodes
	log           *log.Logger
	nodeWrite     sync.Mutex
}
type route struct {
	method, path, permission string
	handler                  gin.HandlerFunc
}

func init() { gin.SetMode(gin.ReleaseMode) }
func New(s *rules.Service, n Nodes, auth Authenticator, logger *log.Logger, options ...Options) *gin.Engine {
	if logger == nil {
		logger = log.Default()
	}
	a := &API{service: s, nodes: n, log: logger, systemOptions: Options{StartedAt: time.Now()}}
	if len(options) > 0 {
		a.systemOptions = options[0]
	}
	if a.systemOptions.nodeAPI != nil {
		a.systemOptions.nodeAPI(a)
	}
	hub := a.systemOptions.hub
	if hub == nil {
		hub = &Hub{}
	}
	hub.init(a, auth)
	e := gin.New()
	if err := e.SetTrustedProxies([]string{"127.0.0.0/8", "::1/128"}); err != nil {
		panic(err)
	}
	e.RemoteIPHeaders = []string{"X-Forwarded-For"}
	e.HandleMethodNotAllowed = true
	routes := []route{
		{"GET", "/events", "ui", hub.events},
		{"GET", "/health", "public", func(c *gin.Context) {
			c.JSON(200, struct {
				Status string `json:"status"`
			}{"ok"})
		}},
		{"POST", "/rules", "all", a.create}, {"POST", "/rules/batch", "all", a.batch},
		{"GET", "/rules", "all", a.list}, {"GET", "/rules/:id", "all", a.get}, {"GET", "/rules/:id/delivery", "all", a.delivery},
		{"PATCH", "/rules/:id", "ui", a.update}, {"PUT", "/rules/:id/enabled", "ui", a.enabled}, {"DELETE", "/rules/:id", "all", a.deleteRule},
		{"GET", "/whitelist", "all", a.listWhitelist}, {"POST", "/whitelist", "ui", a.createWhitelist}, {"DELETE", "/whitelist/:id", "ui", a.deleteWhitelist},
		{"GET", "/capacity", "all", a.capacity}, {"GET", "/system", "all", a.system},
		{"GET", "/traffic/top", "all", a.trafficTop}, {"GET", "/traffic/history", "all", a.trafficHistory},
		{"GET", "/nodes", "all", a.listNodes}, {"POST", "/nodes/:name/sync", "ui", a.sync}, {"POST", "/nodes/:name/reconcile", "ui", a.reconcile},
		{"POST", "/nodes", "admin", a.writeNode}, {"PATCH", "/nodes/:name", "admin", a.writeNode}, {"DELETE", "/nodes/:name", "admin", a.writeNode},
		{"POST", "/nodes/:name/test", "admin", a.testNode}, {"POST", "/nodes/test", "admin", a.testNode},
		{"GET", "/audit", "ui", a.auditPage}, {"GET", "/audit/export", "admin", a.auditExport},
	}
	routes = append(routes, a.accountRoutes()...)
	permissions := map[string]string{}
	for _, r := range routes {
		permissions[r.method+" /api/v1"+r.path] = r.permission
	}
	e.Use(a.recovery(), func(c *gin.Context) {
		p := permissions[c.Request.Method+" "+c.FullPath()]
		if p == "" && c.FullPath() != "" {
			a.fail(c, &Error{Code: "forbidden", Message: "route permission required"})
			return
		}
		if p == "public" {
			c.Next()
			return
		}
		actor, err := rules.Actor{}, &Error{Code: "unauthenticated", Message: "valid actor required"}
		if auth != nil {
			actor, err = auth(c.Request)
		}
		if err != nil {
			a.fail(c, err)
			return
		}
		if p == "ui" && actor.Kind != rules.UI {
			a.fail(c, &Error{Code: "forbidden", Message: "UI actor required"})
			return
		}
		if p == "admin" && !(actor.Kind == rules.UI && actor.Admin) {
			a.fail(c, &Error{Code: "admin_required", Message: "administrator required"})
			return
		}
		actor.Source = sourceIP(c)
		c.Set("actor", actor)
		c.Next()
	})
	for _, r := range routes {
		e.Handle(r.method, "/api/v1"+r.path, r.handler)
	}
	e.NoRoute(func(c *gin.Context) { a.fail(c, &Error{Code: "route_not_found", Message: "route not found"}) })
	e.NoMethod(func(c *gin.Context) { a.fail(c, &Error{Code: "method_not_allowed", Message: "method not allowed"}) })
	if err := checkRoutes(e, permissions); err != nil {
		panic(err)
	}
	return e
}
func checkRoutes(e *gin.Engine, permissions map[string]string) error {
	for _, r := range e.Routes() {
		if _, ok := permissions[r.Method+" "+r.Path]; !ok {
			return fmt.Errorf("route permission missing: %s %s", r.Method, r.Path)
		}
	}
	return nil
}
func actor(c *gin.Context) rules.Actor { return c.MustGet("actor").(rules.Actor) }
func sourceIP(c *gin.Context) string   { return c.ClientIP() }
func (a *API) create(c *gin.Context) {
	var in struct {
		rules.RulePatch
		ClaimRef string `json:"claim_ref"`
	}
	if !a.decode(c, &in, requestBytes) {
		return
	}
	r, e := a.service.Create(actor(c), in.ClaimRef, in.RulePatch)
	if a.serviceError(c, e) {
		return
	}
	nodes := []NodeSummary{}
	for _, n := range a.nodes.Status() {
		nodes = append(nodes, NodeSummary{n.Name, n.Online, n.Incompatible, n.Rules.State})
	}
	status := 201
	if r.Existing {
		status = 200
	}
	c.JSON(status, CreateResponse{ruleDTO(r.Rule), r.Existing, r.Gen, a.service.Epoch(), nodes})
}
func (a *API) batch(c *gin.Context) {
	var in struct {
		ClaimRef string            `json:"claim_ref"`
		Items    []rules.RulePatch `json:"items"`
	}
	if !a.decode(c, &in, batchBytes) {
		return
	}
	if len(in.Items) < 1 || len(in.Items) > batchLimit {
		a.fail(c, &Error{Code: "batch_too_large", Message: fmt.Sprintf("items must contain 1..%d rules; split larger batches into sequential requests of at most %d items", batchLimit, batchLimit), Field: "items"})
		return
	}
	out := BatchResponse{Epoch: a.service.Epoch(), Results: []BatchItem{}}
	var results []rules.BatchResult
	validate := c.Query("validate") == "1"
	if validate {
		results = a.service.BatchValidate(actor(c), in.Items)
	} else {
		results = a.service.BatchCreate(actor(c), in.ClaimRef, in.Items)
	}
	for _, r := range results {
		item := BatchItem{Index: r.Index}
		if r.Error != nil {
			item.Error = a.mapped(r.Error)
		} else {
			dto, existing, gen := ruleDTO(r.Rule), r.Existing, r.Gen
			item.Rule, item.Existing, item.Gen = &dto, &existing, &gen
			if validate {
				item.Gen = nil
			}
		}
		out.Results = append(out.Results, item)
	}
	c.JSON(200, out)
}
func (a *API) pageLimit(c *gin.Context) (int, bool) {
	v := c.DefaultQuery("limit", strconv.Itoa(pageDefault))
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > pageMax {
		a.fail(c, &Error{Code: "bad_request", Message: fmt.Sprintf("limit must be 1..%d", pageMax), Field: "limit"})
		return 0, false
	}
	return n, true
}
func (a *API) list(c *gin.Context) {
	limit, ok := a.pageLimit(c)
	if !ok {
		return
	}
	after, err := strconv.ParseInt(c.DefaultQuery("after", "0"), 10, 64)
	if err != nil || after < 0 {
		a.fail(c, &Error{Code: "bad_request", Message: "after must be a nonnegative logical ID", Field: "after"})
		return
	}
	params := c.Request.URL.Query()
	var rows []store.Rule
	var e *rules.Error
	var counts map[string]int
	if !params.Has("q") && !params.Has("state") && !params.Has("counts") {
		rows, e = a.service.ListPage(after, limit+1)
	} else {
		state := c.Query("state")
		for field, invalid := range map[string]bool{
			"state":  params.Has("state") && state != "drop" && state != "rate_limit" && state != "disabled",
			"counts": params.Has("counts") && c.Query("counts") != "1",
		} {
			if invalid {
				a.fail(c, &Error{Code: "bad_request", Field: field, Message: "invalid " + field})
				return
			}
		}
		rows, counts, e = a.service.QueryPage(c.Query("q"), state, params.Has("counts"), after, limit+1)
	}
	if a.serviceError(c, e) {
		return
	}
	out := Page[RuleDTO]{Items: []RuleDTO{}}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextAfter = rows[limit-1].LogicalID
	}
	for _, r := range rows {
		out.Items = append(out.Items, ruleDTO(r))
	}
	if counts != nil {
		c.JSON(200, struct {
			Page[RuleDTO]
			Counts map[string]int `json:"counts"`
		}{out, counts})
	} else {
		c.JSON(200, out)
	}
}
func (a *API) get(c *gin.Context) {
	r, e := a.service.Get(c.Param("id"))
	if !a.serviceError(c, e) {
		c.JSON(200, ruleDTO(r))
	}
}
func (a *API) update(c *gin.Context) {
	var in rules.RulePatch
	if !a.decode(c, &in, requestBytes) {
		return
	}
	r, e := a.service.Update(actor(c), c.Param("id"), in)
	if !a.serviceError(c, e) {
		c.JSON(200, ruleDTO(r))
	}
}
func (a *API) enabled(c *gin.Context) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !a.decode(c, &in, requestBytes) {
		return
	}
	if in.Enabled == nil {
		a.fail(c, &Error{Code: "bad_request", Message: "enabled is required", Field: "enabled"})
		return
	}
	if !a.serviceError(c, a.service.SetEnabled(actor(c), c.Param("id"), *in.Enabled)) {
		c.JSON(200, in)
	}
}
func (a *API) deleteRule(c *gin.Context) {
	var e *rules.Error
	if actor(c).Kind == rules.UI {
		e = a.service.ForceDelete(actor(c), c.Param("id"))
	} else {
		e = a.service.ReleaseClaim(actor(c), c.Param("id"), c.Query("claim_ref"))
	}
	if !a.serviceError(c, e) {
		c.Status(204)
	}
}
func (a *API) listWhitelist(c *gin.Context) {
	limit, ok := a.pageLimit(c)
	if !ok {
		return
	}
	rows, e := a.service.ListWhitelistPage(c.Query("after"), limit+1)
	if a.serviceError(c, e) {
		return
	}
	out := Page[WhitelistDTO]{Items: []WhitelistDTO{}}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextAfter = rows[limit-1].ID
	}
	for _, w := range rows {
		out.Items = append(out.Items, whitelistDTO(w))
	}
	c.JSON(200, out)
}
func (a *API) createWhitelist(c *gin.Context) {
	var in rules.WhitelistInput
	if !a.decode(c, &in, requestBytes) {
		return
	}
	w, e := a.service.CreateWhitelist(actor(c), in)
	if a.serviceError(c, e) {
		return
	}
	status := 201
	if w.Existing {
		status = 200
	}
	c.JSON(status, struct {
		WhitelistDTO
		Existing bool `json:"existing"`
	}{whitelistDTO(w.Whitelist), w.Existing})
}
func (a *API) deleteWhitelist(c *gin.Context) {
	if !a.serviceError(c, a.service.DeleteWhitelist(actor(c), c.Param("id"))) {
		c.Status(204)
	}
}
func (a *API) listNodes(c *gin.Context) {
	out, err := a.nodesData(a.nodes.Status())
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(200, out)
}
func (a *API) nodeAction(c *gin.Context, action string, call func(string)) {
	for _, n := range a.nodes.Status() {
		if n.Name == c.Param("name") {
			if a.serviceError(c, a.service.Record(actor(c), action, "node:"+n.Name)) {
				return
			}
			call(n.Name)
			c.JSON(202, struct {
				Status string `json:"status"`
			}{"accepted"})
			return
		}
	}
	a.fail(c, &Error{Code: "node_not_found", Message: "node not found"})
}
func (a *API) sync(c *gin.Context)      { a.nodeAction(c, "node.sync", a.nodes.ForceSync) }
func (a *API) reconcile(c *gin.Context) { a.nodeAction(c, "node.reconcile", a.nodes.ReconcileNow) }
func (a *API) delivery(c *gin.Context) {
	if c.Query("epoch") != a.service.Epoch() {
		a.fail(c, &Error{Code: "gen_epoch_mismatch", Message: "process epoch changed"})
		return
	}
	gen, err := strconv.ParseUint(c.Query("gen"), 10, 64)
	if err != nil {
		a.fail(c, &Error{Code: "bad_request", Message: "gen must be an unsigned integer", Field: "gen"})
		return
	}
	r, target, nodes, e := a.service.DeliveryView(c.Param("id"))
	if a.serviceError(c, e) {
		return
	}
	threshold := gen
	if target > threshold {
		threshold = target
	}
	out := DeliveryResponse{r.ID, gen, target, a.service.Epoch(), []DeliveryDTO{}}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, deliveryState(r, threshold, n))
	}
	c.JSON(200, out)
}

func tighter(a, b TightestDTO) bool {
	if a.Exhausted != b.Exhausted {
		return a.Exhausted
	}
	if a.Exhausted {
		return a.Free < b.Free
	}
	return a.Ratio != nil && b.Ratio != nil && *a.Ratio > *b.Ratio
}
func (a *API) capacity(c *gin.Context) {
	o, e := a.service.Occupancy()
	if a.serviceError(c, e) {
		return
	}
	limits := a.service.Limits()
	out := CapacityDTO{Dimensions: []DimensionDTO{}, OverloadedNodes: []OverloadedNodeDTO{}}
	for i, name := range rules.DimensionNames() {
		limit := rules.AdmissionLimit(i, limits.Values[i], o.LogicalReserve)
		d := DimensionDTO{TightestDTO: TightestDTO{Name: name, LimitSource: limits.Sources[i], Free: limit - o.Used[i], Exhausted: limit <= o.Used[i]}, Used: o.Used[i], Limit: limits.Values[i], AdmissionLimit: limit}
		if limit > 0 {
			ratio := float64(d.Used) / float64(limit)
			d.Ratio = &ratio
		}
		out.Dimensions = append(out.Dimensions, d)
		if i == 0 || tighter(d.TightestDTO, out.Tightest) {
			out.Tightest = d.TightestDTO
		}
	}
	out.Candidates.Limit, out.Candidates.FullKeys, out.Candidates.NearKeys = condexpr.MaxCandidates, o.FullKeys, o.NearKeys
	out.Rules.Enabled, out.Rules.Total = o.Used[9], o.Total
	for _, n := range limits.Overloaded {
		d := OverloadedNodeDTO{Name: n.Name, Dims: []CapacityUsedDTO{}}
		for _, v := range n.Dims {
			d.Dims = append(d.Dims, CapacityUsedDTO{v.Dim, v.Limit, v.Used})
		}
		out.OverloadedNodes = append(out.OverloadedNodes, d)
	}
	c.JSON(200, out)
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func (a *API) system(c *gin.Context) {
	o, e := a.service.Occupancy()
	if a.serviceError(c, e) {
		return
	}
	out := SystemDTO{Nodes: []SystemNodeDTO{}}
	out.Controller.StartedAt = stamp(a.systemOptions.StartedAt)
	out.Controller.UptimeSeconds = max(0, time.Since(a.systemOptions.StartedAt).Seconds())
	out.Controller.RulesEnabled, out.Controller.RulesTotal, out.Controller.Whitelist = o.Used[9], o.Total, o.Used[4]
	if a.systemOptions.Database != "" {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if info, err := os.Stat(a.systemOptions.Database + suffix); err == nil {
				out.Controller.DBBytes += info.Size()
			}
		}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	out.Controller.GoMem.AllocBytes, out.Controller.GoMem.SysBytes = mem.Alloc, mem.Sys
	for _, n := range a.nodes.Status() {
		sys := object(n.Stats["system"])
		d := SystemNodeDTO{NodeSummary: NodeSummary{n.Name, n.Online, n.Incompatible, n.Rules.State}, Overloaded: len(n.Overload) > 0, WhitelistState: n.Whitelist.State, StatsAt: stamp(n.StatsAt), HostUptimeSeconds: sys["uptime_seconds"], CPUPercent: sys["cpu_percent"], MemPercent: sys["mem_percent"], LoadAvg1: sys["load_avg_1"], LoadAvg5: sys["load_avg_5"], LoadAvg15: sys["load_avg_15"], Counters: map[string]any{}, Rates: n.Rates, AgentState: n.Stats["agent_state"], Capacity: []CapacityComparisonDTO{}, RuleReconcile: reconcileDTO(n.RuleReconcile), WhitelistReconcile: reconcileDTO(n.WhitelistReconcile)}
		for _, key := range []string{"total_packets", "dropped_packets", "passed_packets", "whitelisted_packets", "rate_limited_packets", "mapped_v6_dropped", "cond_row_missing", "tailcall_fail", "total_bytes", "dropped_bytes", "passed_bytes"} {
			d.Counters[key] = n.Stats[key]
		}
		for i, name := range rules.DimensionNames() {
			entry := object(object(n.Stats["capacity"])[name])
			d.Capacity = append(d.Capacity, CapacityComparisonDTO{name, entry["limit"], entry["used"], o.Used[i]})
		}
		out.Nodes = append(out.Nodes, d)
	}
	c.JSON(200, out)
}
