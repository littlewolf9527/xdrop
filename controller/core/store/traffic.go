package store

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const TrafficMinuteLimit, TrafficHourLimit = 1800000, 200000

var trafficTxObserved func(time.Duration)
var trafficMinutesLoaded func(int)

var trafficMetrics = []string{"dropped_pps", "passed_pps", "dropped_bytes_ps", "passed_bytes_ps"}

const trafficDDL = `(node TEXT NOT NULL, ts INTEGER NOT NULL, n INTEGER NOT NULL,
 dropped_pps_avg REAL NOT NULL, dropped_pps_max REAL NOT NULL, passed_pps_avg REAL NOT NULL, passed_pps_max REAL NOT NULL,
 dropped_bytes_ps_avg REAL NOT NULL, dropped_bytes_ps_max REAL NOT NULL, passed_bytes_ps_avg REAL NOT NULL, passed_bytes_ps_max REAL NOT NULL,
 UNIQUE(node,ts));`
const schemaV6 = `CREATE TABLE traffic_1m ` + trafficDDL + `CREATE INDEX traffic_1m_ts ON traffic_1m(ts);
 CREATE TABLE traffic_1h ` + trafficDDL + `CREATE INDEX traffic_1h_ts ON traffic_1h(ts);
 INSERT INTO settings VALUES('history_retention_days',30);`

type TrafficRow struct {
	Node     string
	T        int64
	N        int
	Avg, Max [4]float64
}

func trafficRows(q Queryer, query string, args ...any) ([]TrafficRow, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficRow{}
	for rows.Next() {
		var v TrafficRow
		dst := []any{&v.Node, &v.T, &v.N}
		for k := range v.Avg {
			dst = append(dst, &v.Avg[k], &v.Max[k])
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func ReadTraffic(q Queryer, hourly bool, node string, from, to int64) ([]TrafficRow, error) {
	table := "traffic_1m"
	if hourly {
		table = "traffic_1h"
	}
	return trafficRows(q, "SELECT * FROM "+table+" WHERE node=? AND ts>=? AND ts<=? ORDER BY ts", node, from, to)
}
func trafficHours(q Queryer, pending []TrafficRow, from, to int64) ([]TrafficRow, error) {
	type key struct {
		node string
		ts   int64
	}
	selected := map[int64]bool{}
	for _, row := range pending {
		if row.T >= from && row.T < to {
			selected[row.T/3600*3600] = true
		}
	}
	hours := []string{}
	for hour := range selected {
		hours = append(hours, fmt.Sprint(hour))
	}
	cols := []string{"m.node", "m.ts/3600*3600", "SUM(m.n)"}
	for _, metric := range trafficMetrics {
		cols = append(cols, "SUM(m."+metric+"_avg*m.n)/SUM(m.n)", "MAX(m."+metric+"_max)")
	}
	exclude := ""
	if len(hours) > 0 {
		exclude = " AND m.ts/3600*3600 NOT IN (" + strings.Join(hours, ",") + ")"
	}
	out, err := trafficRows(q, "SELECT "+strings.Join(cols, ",")+" FROM traffic_1m m WHERE m.ts>=? AND m.ts<?"+exclude+" AND NOT EXISTS (SELECT 1 FROM traffic_1h h WHERE h.node=m.node AND h.ts=m.ts/3600*3600) GROUP BY m.node,m.ts/3600 HAVING SUM(m.n)>0", from, to)
	if err != nil || len(hours) == 0 {
		return out, err
	}
	completed, err := trafficRows(q, "SELECT * FROM traffic_1h WHERE ts IN ("+strings.Join(hours, ",")+")")
	if err != nil {
		return nil, err
	}
	done, seen := map[key]bool{}, map[key]bool{}
	for _, row := range completed {
		done[key{row.Node, row.T}] = true
	}
	stored := []TrafficRow{}
	for hour := range selected {
		rows, err := trafficRows(q, "SELECT * FROM traffic_1m WHERE ts>=? AND ts<? ORDER BY node,ts", hour, hour+3600)
		if err != nil {
			return nil, err
		}
		if trafficMinutesLoaded != nil {
			trafficMinutesLoaded(len(rows))
		}
		stored = append(stored, rows...)
	}
	grouped := map[key]TrafficRow{}
	// Existing minutes win conflicts, matching the minute insert contract.
	for _, row := range append(stored, pending...) {
		minute, hour := key{row.Node, row.T}, key{row.Node, row.T / 3600 * 3600}
		if row.T < from || row.T >= to || done[hour] || seen[minute] {
			continue
		}
		seen[minute] = true
		v := grouped[hour]
		v.Node, v.T = hour.node, hour.ts
		for k := range v.Avg {
			v.Avg[k] += row.Avg[k] * float64(row.N)
			if v.N == 0 || row.Max[k] > v.Max[k] {
				v.Max[k] = row.Max[k]
			}
		}
		v.N += row.N
		grouped[hour] = v
	}
	for _, v := range grouped {
		if v.N == 0 {
			continue
		}
		for k := range v.Avg {
			v.Avg[k] /= float64(v.N)
		}
		out = append(out, v)
	}
	return out, nil
}
func (db *DB) WriteTraffic(minutes []TrafficRow, fromHour int64, now time.Time, limits [2]int, hook func(string)) (capped bool, err error) {
	for i, maximum := range [2]int{TrafficMinuteLimit, TrafficHourLimit} {
		if limits[i] <= 0 || limits[i] > maximum {
			limits[i] = maximum
		}
	}
	settings, err := ReadSettings(db.Reader())
	if err != nil {
		return false, err
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	started := time.Now()
	defer func() {
		tx.Rollback()
		if trafficTxObserved != nil {
			trafficTxObserved(time.Since(started))
		}
	}()
	call := func(phase string) {
		if hook != nil {
			hook(phase)
		}
	}
	hours, err := trafficHours(tx, minutes, fromHour, now.Unix()/3600*3600)
	if err != nil {
		return capped, err
	}
	for i, table := range []string{"traffic_1m", "traffic_1h"} {
		pending := minutes
		if i == 1 {
			pending = hours
		}
		sort.Slice(pending, func(a, b int) bool {
			if pending[a].Node != pending[b].Node {
				return pending[a].Node < pending[b].Node
			}
			return pending[a].T < pending[b].T
		})
		var count int
		if err = tx.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			return capped, err
		}
		remove := count + len(pending) - limits[i]
		if remove > 5000 {
			remove = 5000
		}
		if remove > 0 {
			call("delete")
			result, e := tx.Exec("DELETE FROM "+table+" WHERE rowid IN (SELECT rowid FROM "+table+" ORDER BY ts,node LIMIT ?)", remove)
			if e != nil {
				return capped, e
			}
			n, e := result.RowsAffected()
			if e != nil {
				return capped, e
			}
			count -= int(n)
			capped = capped || n > 0
		}
		quota := limits[i] - count
		if quota < 0 {
			quota = 0
		}
		if len(pending) > quota {
			pending = pending[:quota]
			capped = true
		}
		if len(pending) > 0 {
			call("write")
			stmt, e := tx.Prepare("INSERT INTO " + table + " VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node,ts) DO NOTHING")
			if e != nil {
				return capped, e
			}
			for _, v := range pending {
				args := []any{v.Node, v.T, v.N}
				for k := range v.Avg {
					args = append(args, v.Avg[k], v.Max[k])
				}
				if _, err = stmt.Exec(args...); err != nil {
					break
				}
			}
			stmt.Close()
			if err != nil {
				return capped, err
			}
		}
	}
	for _, table := range []string{"traffic_1m", "traffic_1h"} {
		call("delete")
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE rowid IN (SELECT rowid FROM "+table+" WHERE ts<? ORDER BY ts,node LIMIT 5000)", now.Add(-time.Duration(settings.HistoryRetentionDays)*24*time.Hour).Unix()); err != nil {
			return capped, err
		}
	}
	return capped, tx.Commit()
}

func TrafficTargets(q Queryer, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		args := []any{}
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		rows, err := q.Query(fmt.Sprintf("SELECT id,dst_ip,dst_cidr FROM rules WHERE id IN (%s)", strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, ip, cidr string
			if err = rows.Scan(&id, &ip, &cidr); err != nil {
				break
			}
			if ip == "" {
				ip = cidr
			}
			out[id] = ip
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
