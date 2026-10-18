package orch

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"github.com/mattn/go-sqlite3"
)

type c5cHistoryCounter struct {
	db                      *store.DB
	calls, proposed, capped atomic.Int64
}

func (h *c5cHistoryCounter) WriteTraffic(rows []store.TrafficRow, hour int64, now time.Time, limits [2]int, hook func(string)) (bool, error) {
	capped, e := h.db.WriteTraffic(rows, hour, now, limits, hook)
	if e == nil {
		h.proposed.Add(int64(len(rows)))
		h.calls.Add(1)
		if capped {
			h.capped.Add(1)
		}
	}
	return capped, e
}
func TestC5CLong(t *testing.T) {
	for _, limited := range []bool{false, true} {
		limited := limited
		name := "35d-retention"
		if limited {
			name = "35d-quota"
		}
		t.Run(name, func(t *testing.T) {
			began := time.Now()
			c := c5cNewClock()
			start := c.now()
			path := filepath.Join(t.TempDir(), "history.db")
			db, e := store.Open(path)
			need(t, e == nil, e)
			h := &c5cHistoryCounter{db: db}
			var inserted, deleted [2]atomic.Int64
			conn, e := db.Conn(context.Background())
			need(t, e == nil, e)
			e = conn.Raw(func(raw any) error {
				raw.(*sqlite3.SQLiteConn).RegisterUpdateHook(func(op int, database, table string, rowID int64) {
					i := -1
					if table == "traffic_1m" {
						i = 0
					}
					if table == "traffic_1h" {
						i = 1
					}
					if i >= 0 {
						if op == sqlite3.SQLITE_INSERT {
							inserted[i].Add(1)
						}
						if op == sqlite3.SQLITE_DELETE {
							deleted[i].Add(1)
						}
					}
				})
				return nil
			})
			need(t, e == nil, e)
			need(t, conn.Close() == nil, "release writer")
			o := Options{now: c.now, tick: c.tick, History: h, StatsInterval: time.Minute, ExpireInterval: time.Minute, HealthInterval: 90 * 24 * time.Hour, CheckInterval: 90 * 24 * time.Hour, hitsInterval: 90 * 24 * time.Hour, MergeWindow: time.Nanosecond}
			var capEvents, writes, deleteHooks atomic.Int64
			o.OnEvent = func(ev Event) {
				if ev.Reason == "history_capped" {
					need(t, ev.Node == "", "cap event has node")
					capEvents.Add(1)
				}
			}
			o.historyTx = func(phase string) {
				if phase == "write" {
					writes.Add(1)
				}
				if phase == "delete" {
					deleteHooks.Add(1)
				}
			}
			if limited {
				o.historyLimits = [2]int{10000, 500}
				need(t, store.SetHistoryRetentionDays(db, 90) == nil, "retention90")
			}
			f := newFake()
			o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == string(nc.StatsRoute) {
					v := uint64(c.now().Sub(start) / time.Second)
					return c5cReply(200, fmt.Sprintf(`{"total_packets":%d,"dropped_packets":%d,"passed_packets":%d,"total_bytes":%d,"dropped_bytes":%d,"passed_bytes":%d}`, 3*v, v, 2*v, 300*v, 100*v, 200*v))
				}
				return f.RoundTrip(r)
			})
			specs := []NodeSpec{}
			for i := 0; i < 10; i++ {
				specs = append(specs, c5bSpec(fmt.Sprintf("n%02d", i)))
			}
			m := New(specs, o)
			s := rules.New(db, m)
			s.Now = c.now
			t.Cleanup(func() { m.Stop(); db.Close() })
			m.Start(s)
			settled := func(at time.Time) bool {
				m.mu.Lock()
				defer m.mu.Unlock()
				for _, n := range m.nodes {
					if !n.status.StatsAt.Equal(at) {
						return false
					}
				}
				return true
			}
			c5cSpin(t, func() bool { return c.registered("stats") == 10 && c.registered("expire") == 1 && settled(start) })
			const minutes = 35 * 24 * 60
			for i := 1; i <= minutes+1; i++ {
				c.advance(time.Minute)
				at := c.now()
				cycle := i
				c5cSpin(t, func() bool {
					if !settled(at) || h.calls.Load() != int64(cycle) {
						return false
					}
					m.mu.Lock()
					defer m.mu.Unlock()
					return m.traffic.next == at.Unix()
				})
				if limited {
					for j, table := range []string{"traffic_1m", "traffic_1h"} {
						var count int
						need(t, db.Reader().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count) == nil && count <= o.historyLimits[j], "cycle quota", i, table, count)
					}
				}
				if i%1440 == 0 {
					t.Logf("completed_day=%d cycles=%d inserted_1m=%d deleted_1m=%d capped_cycles=%d", i/1440, i, inserted[0].Load(), deleted[0].Load(), h.capped.Load())
				}
				need(t, time.Since(began) < 12*time.Minute, "long leaf deadline 12m")
			}
			need(t, h.calls.Load() == minutes+1 && h.proposed.Load() == 11*minutes, "complete production cycles", h.calls.Load(), h.proposed.Load())
			need(t, inserted[0].Load() == 11*minutes, "minute insertion count", inserted[0].Load())
			need(t, writes.Load() == minutes+35*24, "write hook exact", writes.Load())
			var counts [2]int64
			for j, table := range []string{"traffic_1m", "traffic_1h"} {
				need(t, db.Reader().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&counts[j]) == nil, "count")
				need(t, counts[j] == inserted[j].Load()-deleted[j].Load(), "independent update hook ledger", table, counts[j], inserted[j].Load(), deleted[j].Load())
			}
			if !limited {
				need(t, counts[0] == 11*30*1440 && counts[1] == 11*(30*24-1), "retention final rows", counts)
				need(t, inserted[1].Load() == 11*35*24 && deleted[0].Load() == 11*5*1440 && deleted[1].Load() == 11*(5*24+1), "exact retention deletes", inserted[1].Load(), deleted[0].Load(), deleted[1].Load())
				for j, table := range []string{"traffic_1m", "traffic_1h"} {
					rows, e := db.Reader().Query("SELECT node,COUNT(*),MIN(ts),MAX(ts) FROM " + table + " GROUP BY node ORDER BY node")
					need(t, e == nil, e)
					sequences := 0
					for rows.Next() {
						var node string
						var n, lo, hi int64
						need(t, rows.Scan(&node, &n, &lo, &hi) == nil, "sequence scan")
						expectedN := int64(30 * 1440)
						expectedLo := start.Add((5*1440 + 1) * time.Minute).Unix()
						expectedHi := start.Add(minutes * time.Minute).Unix()
						if j == 1 {
							expectedN = 30*24 - 1
							expectedLo = start.Add((5*24 + 1) * time.Hour).Unix()
							expectedHi = start.Add((35*24 - 1) * time.Hour).Unix()
						}
						need(t, n == expectedN && lo == expectedLo && hi == expectedHi, "exact per sequence", table, node, n, lo, hi)
						t.Logf("table=%s node=%q n=%d first_ts=%d last_ts=%d", table, node, n, lo, hi)
						sequences++
					}
					need(t, rows.Err() == nil && rows.Close() == nil && sequences == 11, "sequence count")
				}
			} else {
				need(t, counts[0] == 10000 && counts[1] == 500 && deleted[0].Load() > 0 && deleted[1].Load() > 0 && h.capped.Load() > 0, "cap reached", counts)
				c5cSpin(t, func() bool { return capEvents.Load() == h.capped.Load() })
				_, _, capped := m.TrafficMemory("", time.Hour)
				need(t, capped, "recent cap flag")
				t.Logf("quota_cycles=%d limits=10000,500 per_cycle_checked=1 cap_events=%d", minutes+1, capEvents.Load())
			}
			var systemBytes int64
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if info, e := os.Stat(path + suffix); e == nil {
					t.Logf("database_suffix=%q bytes=%d", suffix, info.Size())
					systemBytes += info.Size()
				}
			}
			t.Logf("system.db_bytes=%d measurement=main_plus_wal_plus_shm same_as_system_handler=1", systemBytes)
			t.Logf("minutes_completed=%d sequences=11 cycles=%d proposed=%d inserted=%d,%d deleted=%d,%d final=%v write_hooks=%d delete_hooks=%d elapsed=%s leaf_limit=12m", minutes, h.calls.Load(), h.proposed.Load(), inserted[0].Load(), inserted[1].Load(), deleted[0].Load(), deleted[1].Load(), counts, writes.Load(), deleteHooks.Load(), time.Since(began))
		})
	}
}
