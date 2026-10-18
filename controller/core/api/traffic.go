package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"sort"
	"strconv"
	"time"
)

type topValues struct {
	Target  string   `json:"target"`
	PPS     float64  `json:"dropped_pps"`
	BytesPS float64  `json:"dropped_bytes_ps"`
	Share   *float64 `json:"share"`
}
type topRule struct {
	topValues
	RuleID string `json:"rule_id"`
	Nodes  int    `json:"nodes"`
}
type topTarget struct {
	topValues
	Rules int `json:"rules"`
}
type topResponse struct {
	Rules        []topRule   `json:"rules"`
	Targets      []topTarget `json:"targets"`
	TargetsTotal int         `json:"targets_total"`
	UpdatedAt    *time.Time  `json:"updated_at"`
	Incomplete   bool        `json:"incomplete"`
	TotalPPS     float64     `json:"total_dropped_pps"`
	TotalBytesPS float64     `json:"total_dropped_bytes_ps"`
}
type topMemo struct {
	key      string
	response topResponse
}
type trafficSource interface {
	TrafficInput() orch.TrafficInput
	TrafficMemory(string, time.Duration) ([]store.TrafficRow, time.Time, bool)
}

func (a *API) trafficReader() store.Queryer {
	if a.systemOptions.trafficQuery != nil {
		return a.systemOptions.trafficQuery
	}
	if s := a.systemOptions.NodeStore; s != nil {
		return s.DB.Reader()
	}
	return nil
}
func (a *API) trafficTop(c *gin.Context) {
	n := 5
	if values, present := c.Request.URL.Query()["n"]; present {
		var err error
		if values[0] == "all" {
			n = 0
		} else if n, err = strconv.Atoi(values[0]); err != nil || n < 1 || n > 20 {
			a.fail(c, &Error{Code: "invalid_field", Field: "n", Message: "n must be 1..20"})
			return
		}
	}
	out, err := a.trafficTopData(n)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(200, out)
}
func (a *API) trafficTopData(n int) (topResponse, *Error) {
	out, _, err := a.trafficTopKey(n)
	return out, err
}
func (a *API) trafficTopKey(n int) (topResponse, string, *Error) {
	a.topMu.Lock()
	defer a.topMu.Unlock()
	input := orch.TrafficInput{Names: map[string]bool{}, Rates: map[string]orch.RuleRate{}}
	if source, ok := a.nodes.(trafficSource); ok {
		input = source.TrafficInput()
	}
	q := a.trafficReader()
	missing := []string{}
	if q != nil {
		stored, err := store.Nodes(q)
		if err != nil {
			return topResponse{}, "", &Error{Code: "internal"}
		}
		for _, row := range stored {
			if !input.Names[row.Name] {
				missing = append(missing, row.Name)
			}
		}
	}
	sort.Strings(missing)
	input.Key += fmt.Sprintf("/%q", missing)
	if len(missing) > 0 {
		input.Incomplete, input.DenominatorMissing = true, true
	}
	if cached, ok := a.top[n]; ok && cached.key == input.Key {
		return cached.response, input.Key, nil
	}
	out := topResponse{Rules: []topRule{}, Targets: []topTarget{}, Incomplete: input.Incomplete, TotalPPS: input.DroppedPPS, TotalBytesPS: input.DroppedBytesPS}
	if !input.At.IsZero() {
		at := input.At.UTC()
		out.UpdatedAt = &at
	}
	ids, targets := []string{}, map[string]string{}
	for id, r := range input.Rates {
		if r.PPS > 0 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var denominator float64
	for _, id := range ids {
		denominator += input.Rates[id].PPS
	}
	if q != nil {
		var err error
		targets, err = store.TrafficTargets(q, ids)
		if err != nil {
			return topResponse{}, "", &Error{Code: "internal"}
		}
	}
	share := func(p float64) *float64 {
		if denominator <= 0 {
			return nil
		}
		v := p / denominator
		return &v
	}
	grouped := map[string]topTarget{}
	for _, id := range ids {
		target, exists := targets[id]
		if !exists {
			continue
		}
		r := input.Rates[id]
		v := topValues{target, r.PPS, r.BytesPS, share(r.PPS)}
		out.Rules = append(out.Rules, topRule{v, id, r.Nodes})
		if target == "" {
			continue
		}
		g := grouped[target]
		g.Target, g.PPS, g.BytesPS, g.Rules = target, g.PPS+r.PPS, g.BytesPS+r.BytesPS, g.Rules+1
		grouped[target] = g
	}
	for _, g := range grouped {
		g.Share = share(g.PPS)
		out.Targets = append(out.Targets, g)
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		a, b := out.Rules[i], out.Rules[j]
		if a.PPS != b.PPS {
			return a.PPS > b.PPS
		}
		return a.RuleID < b.RuleID
	})
	sort.Slice(out.Targets, func(i, j int) bool {
		a, b := out.Targets[i], out.Targets[j]
		if a.PPS != b.PPS {
			return a.PPS > b.PPS
		}
		return a.Target < b.Target
	})
	out.TargetsTotal = len(out.Targets)
	if n > 0 && len(out.Rules) > n {
		out.Rules = out.Rules[:n]
	}
	if n > 0 && len(out.Targets) > n {
		out.Targets = out.Targets[:n]
	}
	if a.top == nil {
		a.top = map[int]topMemo{}
	}
	a.top[n] = topMemo{input.Key, out}
	return out, input.Key, nil
}
func (a *API) trafficHistory(c *gin.Context) {
	rangeName, name := c.Query("range"), c.Query("node")
	span, ok := map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[rangeName]
	if !ok {
		a.fail(c, &Error{Code: "invalid_field", Field: "range", Message: "invalid history range"})
		return
	}
	rows, now, capped := []store.TrafficRow{}, time.Now(), false
	source, hasSource := a.nodes.(trafficSource)
	if hasSource {
		rows, now, capped = source.TrafficMemory(name, span)
	}
	q := a.trafficReader()
	if name != "" {
		known := false
		if q != nil {
			stored, err := store.Nodes(q)
			if err != nil {
				a.fail(c, &Error{Code: "internal"})
				return
			}
			for _, row := range stored {
				known = known || row.Name == name
			}
		} else if hasSource {
			known = source.TrafficInput().Names[name]
		}
		if !known {
			a.fail(c, &Error{Code: "node_not_found", Message: "node not found"})
			return
		}
	}
	step := 5
	if span > time.Hour {
		step = 60
		if span > 24*time.Hour {
			step = 3600
		}
		rows = []store.TrafficRow{}
		if q != nil {
			var err error
			rows, err = store.ReadTraffic(q, step == 3600, name, now.Add(-span).Unix(), now.Unix())
			if err != nil {
				a.fail(c, &Error{Code: "internal"})
				return
			}
		}
	}
	points := []map[string]any{}
	for _, p := range rows {
		point := map[string]any{"t": p.T}
		for k, key := range []string{"dropped_pps", "passed_pps", "dropped_bytes_ps", "passed_bytes_ps"} {
			point[key] = p.Avg[k]
			if step > 5 {
				point[key+"_max"] = p.Max[k]
			}
		}
		points = append(points, point)
	}
	c.JSON(200, gin.H{"range": rangeName, "step_s": step, "node": name, "capped": capped, "points": points})
}
