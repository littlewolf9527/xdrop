package store

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func c5cDB(t *testing.T) *DB {
	t.Helper()
	db, e := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func c5cMust(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func c5cCount(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	c5cMust(t, db.Reader().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
	return n
}
func c5cSeed(t *testing.T, db *DB, table string, n int, ts int64) {
	t.Helper()
	_, e := db.Exec("WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM s WHERE x<?) INSERT INTO "+table+" SELECT printf('old-%08d',x),?,1,1,1,1,1,1,1,1,1 FROM s", n, ts)
	c5cMust(t, e)
}
func TestC5CStore(t *testing.T) {
	t.Run("migration", func(t *testing.T) {
		db := c5cDB(t)
		_, e := db.Exec("ALTER TABLE claims DROP COLUMN expires_at; DROP TABLE traffic_1m; DROP TABLE traffic_1h; DELETE FROM settings WHERE key='history_retention_days'; UPDATE schema_version SET version=5")
		c5cMust(t, e)
		c5cMust(t, db.Migrate())
		c5cMust(t, db.Migrate())
		var version, tables, setting int
		c5cMust(t, db.QueryRow("SELECT version FROM schema_version").Scan(&version))
		c5cMust(t, db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('traffic_1m','traffic_1h') AND type='table'").Scan(&tables))
		c5cMust(t, db.QueryRow("SELECT value FROM settings WHERE key='history_retention_days'").Scan(&setting))
		if version != 7 || tables != 2 || setting != 30 {
			t.Fatal(version, tables, setting)
		}
		_, e = db.Exec("UPDATE schema_version SET version=8")
		c5cMust(t, e)
		if db.Migrate() == nil {
			t.Fatal("v8 accepted")
		}
		t.Log("v5_to_v6=1 idempotent=1 tables=2 retention_default=30 v7_rejected=1")
	})
	t.Run("hour-weighted-restart", func(t *testing.T) {
		db := c5cDB(t)
		start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		a := TrafficRow{Node: "a", T: start.Unix(), N: 2, Avg: [4]float64{10, 20, 100, 200}, Max: [4]float64{11, 21, 101, 201}}
		b := TrafficRow{Node: "a", T: start.Add(time.Minute).Unix(), N: 1, Avg: [4]float64{40, 50, 400, 500}, Max: [4]float64{41, 51, 401, 501}}
		_, e := db.WriteTraffic([]TrafficRow{a, b}, 0, start.Add(2*time.Minute), [2]int{}, nil)
		c5cMust(t, e)
		if c5cCount(t, db, "traffic_1h") != 0 {
			t.Fatal("early hour")
		}
		_, e = db.WriteTraffic(nil, 0, start.Add(time.Hour), [2]int{}, nil)
		c5cMust(t, e)
		rows, e := ReadTraffic(db.Reader(), true, "a", 0, start.Add(time.Hour).Unix())
		c5cMust(t, e)
		if len(rows) != 1 || rows[0].N != 3 || rows[0].Avg[0] != 20 || rows[0].Max[0] != 41 {
			t.Fatal(rows)
		}
		_, e = db.WriteTraffic(nil, 0, start.Add(2*time.Hour), [2]int{}, nil)
		c5cMust(t, e)
		if c5cCount(t, db, "traffic_1h") != 1 {
			t.Fatal("duplicate hour")
		}
		t.Log("hour_before_end_rows=0 after_end_rows=1 n=3 weighted_avg=20 max=41 restart_backfill=1")
	})
	t.Run("retention-boundary-batch", func(t *testing.T) {
		db := c5cDB(t)
		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		cutoff := now.Add(-30 * 24 * time.Hour).Unix()
		for _, table := range []string{"traffic_1m", "traffic_1h"} {
			c5cSeed(t, db, table, 5001, cutoff-1)
			_, e := db.Exec("INSERT INTO "+table+" VALUES('boundary',?,1,1,1,1,1,1,1,1,1)", cutoff)
			c5cMust(t, e)
		}
		_, e := db.WriteTraffic(nil, now.Unix(), now, [2]int{}, nil)
		c5cMust(t, e)
		for _, table := range []string{"traffic_1m", "traffic_1h"} {
			if n := c5cCount(t, db, table); n != 2 {
				t.Fatal(table, n)
			}
			var n int
			c5cMust(t, db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE node='boundary'").Scan(&n))
			if n != 1 {
				t.Fatal("strict boundary")
			}
		}
		_, e = db.WriteTraffic(nil, now.Unix(), now, [2]int{}, nil)
		c5cMust(t, e)
		for _, table := range []string{"traffic_1m", "traffic_1h"} {
			if c5cCount(t, db, table) != 1 {
				t.Fatal("second batch")
			}
		}
		t.Log("per_table_expired=5001 first_deleted=5000 first_expired_remaining=1 boundary_retained=1 second_deleted=1")
	})
	for _, target := range []string{"traffic_1m", "traffic_1h"} {
		target := target
		t.Run("quota-"+target, func(t *testing.T) {
			db := c5cDB(t)
			now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
			c5cSeed(t, db, target, 6001, now.Add(-2*time.Hour).Unix())
			pending := []TrafficRow{{Node: "", T: now.Add(-time.Hour).Unix(), N: 1}}
			for i := 0; i < 7000; i++ {
				pending = append(pending, TrafficRow{Node: fmt.Sprintf("new-%08d", i), T: now.Add(-time.Hour).Unix(), N: 1})
			}
			limits := [2]int{6002, 200000}
			if target == "traffic_1h" {
				limits = [2]int{10000, 6002}
			}
			capped, e := db.WriteTraffic(pending, 0, now, limits, nil)
			c5cMust(t, e)
			if !capped || c5cCount(t, db, target) != 6002 {
				t.Fatal("quota", capped, c5cCount(t, db, target))
			}
			var old, aggregate int
			c5cMust(t, db.QueryRow("SELECT COUNT(*) FROM "+target+" WHERE node LIKE 'old-%'").Scan(&old))
			c5cMust(t, db.QueryRow("SELECT COUNT(*) FROM "+target+" WHERE node='' ").Scan(&aggregate))
			if old != 1001 || aggregate != 1 {
				t.Fatal("priority/delete bound", old, aggregate)
			}
			// Full table accepts a later aggregate and removes exactly the needed oldest row.
			p := TrafficRow{T: now.Unix(), N: 1}
			capped, e = db.WriteTraffic([]TrafficRow{p}, now.Unix(), now.Add(time.Hour), limits, nil)
			c5cMust(t, e)
			if !capped || c5cCount(t, db, target) > 6002 {
				t.Fatal("ring cap")
			}
			var latest int
			c5cMust(t, db.QueryRow("SELECT COUNT(*) FROM "+target+" WHERE node='' AND ts=?", now.Unix()).Scan(&latest))
			if latest != 1 {
				t.Fatal("latest not accepted")
			}
			t.Logf("table=%s R=6001 H=6002 B=7001 cap_deleted=5000 quota=5001 dropped=2000 aggregate_accepted=1 cycles=2 rows_each<=6002 latest=1", target)
		})
	}
	t.Run("only-hour-over-cap", func(t *testing.T) {
		db := c5cDB(t)
		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		c5cSeed(t, db, "traffic_1h", 11001, now.Add(-time.Hour).Unix())
		for i, want := range []int{6001, 1001, 1000} {
			capped, e := db.WriteTraffic(nil, now.Unix(), now, [2]int{1000, 1000}, nil)
			c5cMust(t, e)
			if !capped || c5cCount(t, db, "traffic_1h") != want || c5cCount(t, db, "traffic_1m") != 0 {
				t.Fatal("hour cap", i)
			}
			t.Logf("cycle=%d hour_rows=%d cap_deleted=%d", i+1, want, []int{5000, 5000, 1}[i])
		}
	})
	t.Run("separate-batches", func(t *testing.T) {
		db := c5cDB(t)
		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		for _, table := range []string{"traffic_1m", "traffic_1h"} {
			c5cSeed(t, db, table, 11001, now.Add(-31*24*time.Hour).Unix())
		}
		capped, e := db.WriteTraffic(nil, now.Unix(), now, [2]int{1000, 1000}, nil)
		c5cMust(t, e)
		for _, table := range []string{"traffic_1m", "traffic_1h"} {
			if !capped || c5cCount(t, db, table) != 1001 {
				t.Fatal("batch budgets", table)
			}
		}
		t.Log("per_table_cap_deleted=5000 retention_deleted=5000 total_deleted=10000 remaining=1001")
	})
	t.Run("transaction-timing", func(t *testing.T) {
		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		defer func() { trafficTxObserved = nil }()
		for _, kind := range []string{"write", "delete"} {
			db := c5cDB(t)
			samples := []time.Duration{}
			trafficTxObserved = func(d time.Duration) { samples = append(samples, d) }
			for i := 0; i < 100; i++ {
				pending := []TrafficRow{}
				if kind == "write" {
					for j := 0; j < 11; j++ {
						pending = append(pending, TrafficRow{Node: fmt.Sprintf("%d/%d", i, j), T: now.Unix(), N: 1})
					}
				} else {
					for _, table := range []string{"traffic_1m", "traffic_1h"} {
						_, e := db.Exec("WITH RECURSIVE x(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM x WHERE i<5000) INSERT INTO "+table+" SELECT CAST(i AS TEXT),?,1,0,0,0,0,0,0,0,0 FROM x", now.Add(-31*24*time.Hour).Unix())
						c5cMust(t, e)
					}
				}
				_, e := db.WriteTraffic(pending, now.Unix(), now, [2]int{}, nil)
				c5cMust(t, e)
				if kind == "delete" {
					var remaining int
					c5cMust(t, db.Reader().QueryRow("SELECT (SELECT COUNT(*) FROM traffic_1m)+(SELECT COUNT(*) FROM traffic_1h)").Scan(&remaining))
					if remaining != 0 {
						t.Fatal("each measured deletion must remove 5000 rows per table", remaining)
					}
				}
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			if len(samples) != 100 {
				t.Fatal("sample count")
			}
			t.Logf("history_transaction_kind=%s samples=100 p99=%s max=%s includes_commit_and_rollback_cleanup=1 write_rows_per_sample=11 delete_rows_per_sample=10000", kind, samples[98], samples[99])
		}
	})
}

func TestC5CRetentionChange(t *testing.T) {
	db := c5cDB(t)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for _, table := range []string{"traffic_1m", "traffic_1h"} {
		c5cSeed(t, db, table, 1, now.Add(-2*24*time.Hour).Unix())
	}
	_, e := db.WriteTraffic(nil, now.Unix(), now, [2]int{}, nil)
	c5cMust(t, e)
	if c5cCount(t, db, "traffic_1m") != 1 || c5cCount(t, db, "traffic_1h") != 1 {
		t.Fatal("old retention")
	}
	c5cMust(t, SetHistoryRetentionDays(db, 1))
	_, e = db.WriteTraffic(nil, now.Unix(), now, [2]int{}, nil)
	c5cMust(t, e)
	if c5cCount(t, db, "traffic_1m") != 0 || c5cCount(t, db, "traffic_1h") != 0 {
		t.Fatal("changed retention next cycle")
	}
	t.Log("before_retention=30 after_retention=1 next_cycle_deleted_each=1")
}

func TestC5CHistory(t *testing.T) {
	t.Run("hour-settle-bounded-load", func(t *testing.T) {
		db := c5cDB(t)
		start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Unix()
		const hours, sequences = 48, 3
		recent := start + (hours-1)*3600
		now := time.Unix(start+hours*3600, 0)
		tx, e := db.Begin()
		c5cMust(t, e)
		defer tx.Rollback()
		stmt, e := tx.Prepare("INSERT INTO traffic_1m VALUES(?,?,?,?,?,?,?,?,?,?,?)")
		c5cMust(t, e)
		for h := 0; h < hours; h++ {
			for node := 0; node < sequences; node++ {
				for minute := 0; minute < 60; minute++ {
					args := []any{fmt.Sprintf("n%d", node), start + int64(h)*3600 + int64(minute)*60, minute%3 + 1}
					for k := 0; k < 4; k++ {
						v := 1000*node + 100*h + minute + 10*k
						args = append(args, v, v+k+1)
					}
					_, e = stmt.Exec(args...)
					c5cMust(t, e)
				}
			}
		}
		c5cMust(t, stmt.Close())
		c5cMust(t, tx.Commit())
		if c5cCount(t, db, "traffic_1m") != hours*sequences*60 || c5cCount(t, db, "traffic_1h") != 0 {
			t.Fatal("backfill prerequisites")
		}
		pending := []TrafficRow{
			{Node: "n0", T: recent, N: 999, Avg: [4]float64{99999, 99999, 99999, 99999}, Max: [4]float64{99999, 99999, 99999, 99999}},
			{Node: "pending", T: recent, N: 2, Avg: [4]float64{10, 20, 30, 40}, Max: [4]float64{11, 21, 31, 41}},
			{Node: "pending", T: recent + 60, N: 1, Avg: [4]float64{40, 50, 60, 70}, Max: [4]float64{41, 51, 61, 71}},
		}
		loaded, calls := 0, 0
		trafficMinutesLoaded = func(n int) { loaded += n; calls++ }
		defer func() { trafficMinutesLoaded = nil }()
		capped, e := db.WriteTraffic(pending, 0, now, [2]int{}, nil)
		c5cMust(t, e)
		if capped || c5cCount(t, db, "traffic_1h") != hours*sequences+1 {
			t.Fatal("all ended hours must be settled", capped)
		}
		checked := 0
		for node := 0; node < sequences; node++ {
			rows, e := ReadTraffic(db.Reader(), true, fmt.Sprintf("n%d", node), 0, now.Unix())
			c5cMust(t, e)
			if len(rows) != hours {
				t.Fatal("hour count", node, len(rows))
			}
			for h, row := range rows {
				if row.T != start+int64(h)*3600 || row.N != 120 {
					t.Fatal("hour identity/n", row)
				}
				for k := 0; k < 4; k++ {
					// Twenty repetitions of weights 1,2,3: sum=120; sum(minute*weight)=3580.
					avg := float64((1000*node+100*h+10*k)*120+3580) / 120
					max := float64(1000*node + 100*h + 60 + 11*k)
					if row.Avg[k] != avg || row.Max[k] != max {
						t.Fatal("independent aggregate", row, k, avg, max)
					}
				}
				checked++
			}
		}
		rows, e := ReadTraffic(db.Reader(), true, "pending", 0, now.Unix())
		c5cMust(t, e)
		if len(rows) != 1 || rows[0].T != recent || rows[0].N != 3 || rows[0].Avg != [4]float64{20, 30, 40, 50} || rows[0].Max != [4]float64{41, 51, 61, 71} {
			t.Fatal("pending input", rows)
		}
		checked++
		t.Logf("fromHour=0 stored_minutes=8640 stored_hours_before=0 pending_hours=1 checked_hours=%d all_n_avg_max_equal=1 loaded_minutes=%d recent_stored_minutes=180 pending_minutes=%d bound=%d read_calls=%d", checked, loaded, len(pending), sequences*60+len(pending), calls)
		if checked != hours*sequences+1 || calls != 1 || loaded != sequences*60 || loaded > sequences*60+len(pending) {
			t.Fatal("minute loading exceeds pending-hour bound", checked, calls, loaded)
		}
		trafficMinutesLoaded = nil
		zero := c5cDB(t)
		for _, ts := range []int64{start, recent} {
			_, e = zero.Exec("INSERT INTO traffic_1m VALUES('zero',?,0,0,0,0,0,0,0,0,0)", ts)
			c5cMust(t, e)
		}
		_, e = zero.WriteTraffic([]TrafficRow{{Node: "pending-zero", T: recent}}, 0, now, [2]int{}, nil)
		c5cMust(t, e)
		if c5cCount(t, zero, "traffic_1h") != 0 {
			t.Fatal("zero n hour written")
		}
		t.Log("zero_n_sql_hour_skipped=1 zero_n_merged_hours_skipped=2")
	})
	t.Run("hour-before-cap-delete", func(t *testing.T) {
		now := time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC)
		start := now.Add(-time.Hour).Unix()
		for _, pendingMinute := range []bool{false, true} {
			pendingMinute := pendingMinute
			t.Run(fmt.Sprintf("pending-minute-%t", pendingMinute), func(t *testing.T) {
				db := c5cDB(t)
				first := 0
				if pendingMinute {
					first = 1
				}
				for i := first; i < 60; i++ {
					value := 0
					if i == 0 {
						value = 100
					}
					_, e := db.Exec("INSERT INTO traffic_1m VALUES('a',?,1,?,?,0,0,0,0,0,0)", start+int64(i)*60, value, value)
					c5cMust(t, e)
				}
				pending := []TrafficRow{{T: now.Unix(), N: 1}}
				limit := 60
				if pendingMinute {
					limit = 1
					pending = append(pending, TrafficRow{Node: "a", T: start, N: 1, Avg: [4]float64{100}, Max: [4]float64{100}})
				}
				capped, e := db.WriteTraffic(pending, start, now.Add(time.Minute), [2]int{limit, 100}, nil)
				c5cMust(t, e)
				rows, e := ReadTraffic(db.Reader(), true, "a", start, now.Unix())
				c5cMust(t, e)
				if len(rows) != 1 || rows[0].N != 60 || rows[0].Avg[0] != 100.0/60 || rows[0].Max[0] != 100 || !capped || c5cCount(t, db, "traffic_1m") != limit {
					t.Fatal("hour input lost before settlement", rows, capped, c5cCount(t, db, "traffic_1m"))
				}
				var absent int
				c5cMust(t, db.Reader().QueryRow("SELECT COUNT(*) FROM traffic_1m WHERE node='a' AND ts=?", start).Scan(&absent))
				if absent != 0 {
					t.Fatal("high minute must be deleted or rejected", absent)
				}
				t.Logf("pending_high_minute=%t hour_n=60 hour_avg=%.15f hour_max=100 minute_rows=%d H=%d capped=true high_minute_not_stored=1", pendingMinute, rows[0].Avg[0], limit, limit)
			})
		}
	})
}
