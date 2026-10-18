package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type labProcess struct {
	cmd     *exec.Cmd
	done    chan error
	stopped bool
}

func labProcessStart(t *testing.T, binary, config, path string) *labProcess {
	t.Helper()
	after := labAccountBefore(t, binary, config, path)
	file, err := os.Create(path)
	require(t, err == nil, err)
	cmd := exec.Command(binary, "-config", config)
	cmd.Stdout, cmd.Stderr = file, file
	require(t, cmd.Start() == nil, "process start")
	p := &labProcess{cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait(); file.Close() }()
	t.Cleanup(func() {
		if !p.stopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-p.done:
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				<-p.done
			}
		}
	})
	after()
	return p
}
func labSeed(t *testing.T, path string) {
	t.Helper()
	db, err := store.Open(path)
	require(t, err == nil, err)
	defer db.Close()
	tx, err := db.Begin()
	require(t, err == nil, err)
	defer tx.Rollback()
	for i := 0; i < 500000; i++ {
		match := store.Match{SrcIP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Protocol: "tcp", Action: "drop"}
		if i >= 400000 {
			j := i - 400000
			match.SrcIP = ""
			if j < 50000 {
				match.SrcCIDR = fmt.Sprintf("172.16.%d.%d/32", j/256, j%256)
				match.DstCIDR = fmt.Sprintf("192.168.%d.%d/32", j/256, j%256)
			} else {
				j -= 50000
				match.SrcCIDR = fmt.Sprintf("2001:db8:1::%x/128", j+1)
				match.DstCIDR = fmt.Sprintf("2001:db8:2::%x/128", j+1)
			}
		}
		c, e := rules.Canonicalize(match)
		require(t, e == nil, e)
		id, err := store.NextLogicalID(tx)
		require(t, err == nil, err)
		r := store.Rule{ID: fmt.Sprintf("rule_%032x", id), LogicalID: id, Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true, CreatedAt: "2026-10-11T00:00:00Z", UpdatedAt: "2026-10-11T00:00:00Z", CreatedBy: "ui", UpdatedBy: "ui"}
		require(t, store.InsertRule(tx, r) == nil && store.Claim(tx, r.ID, "ui", "", r.CreatedAt) == nil, "seed persistence")
	}
	require(t, tx.Commit() == nil, "seed commit")
	report, e := rules.Prepare(db)
	require(t, e == nil && len(report.Violations) == 0, "seed Prepare", e, report)
}
func labCall(client *http.Client, base, method, path, body string) ([]byte, int, time.Time, time.Duration, error) {
	start := time.Now()
	r, err := http.NewRequest(method, base+"/api/v1"+path, strings.NewReader(body))
	if err != nil {
		return nil, 0, time.Now(), 0, err
	}
	r.Header.Set("Authorization", "Bearer "+labBearer(base))
	w, err := client.Do(r)
	if err != nil {
		return nil, 0, time.Now(), time.Since(start), err
	}
	defer w.Body.Close()
	data, err := io.ReadAll(w.Body)
	labAccountResponse(base, path, data)
	at := time.Now()
	return data, w.StatusCode, at, at.Sub(start), err
}
func labWait(t *testing.T, duration time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("lab deadline expired")
}
func labP99(values []time.Duration) time.Duration {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[(len(values)*99+99)/100-1]
}
func TestCtlCut3Lab(t *testing.T) {
	if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
		for _, id := range []string{"L3-up", "L3-write", "L3-stop"} {
			id := id
			t.Run(id, func(t *testing.T) { t.Skip("requires owned lab namespaces and native binaries") })
		}
		return
	}
	root := t.TempDir()
	dir := filepath.Join(root, "database")
	require(t, os.Mkdir(dir, 0700) == nil, "database directory")
	dbpath := filepath.Join(dir, "controller.db")
	base := os.Getenv("XDROP_CTLCUT3_URL")
	logs := os.Getenv("XDROP_CTLCUT2_LOG_DIR")
	keyfile := os.Getenv("XDROP_CTLCUT2_KEY_FILE")
	agentURL := os.Getenv("XDROP_CTLCUT2_AGENT_URL")
	key, err := os.ReadFile(keyfile)
	require(t, err == nil, err)
	spec := nc.NodeSpec{Name: "lab", BaseURL: agentURL, Key: nc.Secret(strings.TrimRight(string(key), "\r\n"))}
	direct, err := nc.New(spec, nc.Options{})
	require(t, err == nil, err)
	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	var ctl *labProcess
	sampleIDs := map[string]bool{}
	parent := t
	if !t.Run("L3-up", func(t *testing.T) {
		labSeed(t, dbpath)
		labProcessStart(parent, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L3-agent.log"))
		config := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbpath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(config, []byte(text), 0600) == nil, "configuration write")
		labNodeInit(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), config, "lab", agentURL, keyfile)
		ctl = labProcessStart(parent, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), config, filepath.Join(logs, "L3-controller.log"))
		labWait(t, 5*time.Minute, func() bool {
			data, status, _, _, err := labCall(client, base, "GET", "/health", "")
			return err == nil && status == 200 && bytes.Equal(bytes.TrimSpace(data), []byte(`{"status":"ok"}`))
		})
		labWait(t, 5*time.Minute, func() bool {
			data, status, _, _, err := labCall(client, base, "GET", "/nodes", "")
			var result struct {
				Nodes []NodeDTO `json:"nodes"`
			}
			_ = json.Unmarshal(data, &result)
			return err == nil && status == 200 && len(result.Nodes) == 1 && result.Nodes[0].Online && result.Nodes[0].Rules.State == "normal" && result.Nodes[0].Whitelist.State == "normal"
		})
	}) {
		return
	}
	if !t.Run("L3-write", func(t *testing.T) {
		type receipt struct {
			r  CreateResponse
			at time.Time
		}
		type observation struct {
			id      string
			latency time.Duration
			err     error
		}
		observed := make(chan observation, 50)
		watch := func(item receipt) {
			go func() {
				end := item.at.Add(60 * time.Second)
				for time.Now().Before(end) {
					data, status, _, _, err := labCall(client, base, "GET", fmt.Sprintf("/rules/%s/delivery?gen=%d&epoch=%s", item.r.ID, item.r.Gen, item.r.Epoch), "")
					var v DeliveryResponse
					_ = json.Unmarshal(data, &v)
					if err == nil && status == 200 && len(v.Nodes) == 1 && v.Nodes[0].State == "confirmed" {
						observed <- observation{item.r.ID, time.Since(item.at), nil}
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				observed <- observation{item.r.ID, time.Since(item.at), fmt.Errorf("receipt exceeded 60s")}
			}()
		}
		singles, batches := []time.Duration{}, []time.Duration{}
		singleSuccess, batchSuccess := 0, 0
		for i := 0; i < 1000; i++ {
			data, status, at, elapsed, err := labCall(client, base, "POST", "/rules", body(i+1))
			require(t, err == nil && status == 201, "single write", i, status, err)
			var r CreateResponse
			require(t, json.Unmarshal(data, &r) == nil && !r.Existing && r.ID != "" && r.Gen > 0, "single receipt")
			singleSuccess++
			singles = append(singles, elapsed)
			if i < 25 {
				sampleIDs[r.ID] = true
				watch(receipt{r, at})
			}
		}
		for batch := 0; batch < 20; batch++ {
			items := []json.RawMessage{}
			for i := 0; i < 500; i++ {
				items = append(items, json.RawMessage(body(1001+batch*500+i)))
			}
			input, _ := json.Marshal(struct {
				Items []json.RawMessage `json:"items"`
			}{items})
			data, status, at, elapsed, err := labCall(client, base, "POST", "/rules/batch", string(input))
			require(t, err == nil && status == 200, "batch write", batch, status, err)
			var b BatchResponse
			require(t, json.Unmarshal(data, &b) == nil && len(b.Results) == 500, "batch item count")
			batches = append(batches, elapsed)
			for i, item := range b.Results {
				require(t, item.Index == i && item.Error == nil && item.Rule != nil && item.Gen != nil && item.Existing != nil && !*item.Existing, "batch success item", i)
				batchSuccess++
				if batch == 0 && i < 25 {
					r := CreateResponse{RuleDTO: *item.Rule, Gen: *item.Gen, Epoch: b.Epoch}
					sampleIDs[r.ID] = true
					watch(receipt{r, at})
				}
			}
		}
		require(t, len(singles) == 1000 && len(batches) == 20 && singleSuccess == 1000 && batchSuccess == 10000 && len(sampleIDs) == 50, "workload counts")
		singleP99, batchP99 := labP99(singles), labP99(batches)
		t.Logf("WRITE singles=%d success=%d p99=%s batches=%d items_success=%d p99=%s", len(singles), singleSuccess, singleP99, len(batches), batchSuccess, batchP99)
		require(t, singleP99 < 2*time.Second && batchP99 < 2*time.Second, "write p99 exceeded")
		confirmed := map[string]bool{}
		for i := 0; i < 50; i++ {
			select {
			case o := <-observed:
				require(t, o.err == nil && o.latency <= 60*time.Second && !confirmed[o.id], "confirmation", o)
				confirmed[o.id] = true
				t.Logf("CONFIRMED id=%s latency=%s", o.id, o.latency)
			case <-time.After(61 * time.Second):
				t.Fatal("missing confirmation observation")
			}
		}
		found := map[string]bool{}
		pages := 1
		for page := 1; page <= pages; page++ {
			result, e := direct.Rules(context.Background(), page, 1000)
			require(t, e == nil, e)
			pages = result.Pagination.Pages
			for _, r := range result.Rules {
				if sampleIDs[r.ID] {
					found[r.ID] = true
				}
			}
		}
		require(t, len(found) == 50, "independent node readback", len(found))
		t.Logf("READBACK unique_samples=%d pages=%d", len(found), pages)
	}) {
		return
	}
	if !t.Run("L3-stop", func(t *testing.T) {
		labAccountScan(t)
		require(t, ctl.cmd.Process.Signal(syscall.SIGTERM) == nil, "SIGTERM")
		select {
		case err := <-ctl.done:
			ctl.stopped = true
			require(t, err == nil, "controller exit", err)
		case <-time.After(30 * time.Second):
			t.Fatal("controller shutdown timeout")
		}
		entries, err := os.ReadDir(dir)
		require(t, err == nil && len(entries) == 1 && entries[0].Name() == "controller.db", "single-file witness", entries, err)
		t.Log("STOP exited=1 exit_code=0 database_files={controller.db}")
	}) {
		return
	}
	// After the binary exits, run the same handler stack with measurable pools.
	// There is never more than one active controller for this node.
	labMetrics(t, dbpath, spec, sampleIDs)
}
func labMetrics(t *testing.T, path string, spec nc.NodeSpec, ids map[string]bool) {
	db, err := store.Open(path)
	require(t, err == nil, err)
	defer db.Close()
	m := orch.New([]nc.NodeSpec{spec}, orch.Options{ReconcileInterval: time.Hour})
	samples := make(chan time.Duration, 1000)
	status := DeliveryStatus(m)
	s := rules.New(db, m, func() []rules.DeliveryNode {
		start := time.Now()
		result := status()
		samples <- time.Since(start)
		return result
	})
	m.Start(s)
	defer m.Stop()
	labWait(t, 5*time.Minute, func() bool { return m.Status()[0].Rules.Confirmable })
	e := New(s, m, testActor, log.New(io.Discard, "", 0))
	reader := db.Reader().(*sql.DB)
	var wg sync.WaitGroup
	failures := make(chan int, 400)
	var id string
	for key := range ids {
		id = key
		break
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				for _, path := range []string{"/rules?limit=1000", fmt.Sprintf("/rules/%s/delivery?gen=0&epoch=%s", id, s.Epoch())} {
					r := httptest.NewRequest("GET", "/api/v1"+path, nil)
					r.Header.Set("X-Xdrop-Actor", "ui")
					w := httptest.NewRecorder()
					e.ServeHTTP(w, r)
					failures <- w.Code
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	peak := 0
	for {
		select {
		case <-done:
			goto complete
		case <-time.After(time.Millisecond):
			if n := reader.Stats().OpenConnections; n > peak {
				peak = n
			}
		}
	}
complete:
	close(samples)
	close(failures)
	for code := range failures {
		require(t, code == 200, "metrics HTTP request", code)
	}
	values := []time.Duration{}
	for d := range samples {
		values = append(values, d)
	}
	require(t, len(values) == 200 && peak > 0, "metrics observations", len(values), peak)
	t.Logf("METRICS delivery_locked_status_calls=%d status_p99=%s status_max=%s concurrent_http_read_pool_peak=%d pool_max_open=%d", len(values), labP99(values), values[len(values)-1], peak, reader.Stats().MaxOpenConnections)
}
