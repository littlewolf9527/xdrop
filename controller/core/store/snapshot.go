package store

// NodeRow contains only the columns transmitted to a node.
type NodeRow struct {
	ID        string
	LogicalID int64
	Match
}

func EnabledForNode(q Queryer) ([]NodeRow, error) {
	rows, err := q.Query("SELECT id,logical_id,src_ip,dst_ip,src_cidr,dst_cidr,src_port,dst_port,protocol,ttl,dscp,icmp_type,icmp_code,fragment,pkt_len,tcp_flags,match_anomaly,action,rate_limit FROM rules WHERE enabled=1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeRow{}
	for rows.Next() {
		var r NodeRow
		if err := rows.Scan(&r.ID, &r.LogicalID, &r.SrcIP, &r.DstIP, &r.SrcCIDR, &r.DstCIDR, &r.SrcPort, &r.DstPort, &r.Protocol, &r.TTL, &r.DSCP, &r.ICMPType, &r.ICMPCode, &r.Fragment, &r.PktLen, &r.TCPFlags, &r.MatchAnomaly, &r.Action, &r.RateLimit); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func EnabledByGroups(q Queryer, keys []string) (map[string][]Rule, error) {
	out := make(map[string][]Rule, len(keys))
	for _, key := range keys {
		rows, err := EnabledByGroup(q, key)
		if err != nil {
			return nil, err
		}
		out[key] = rows
	}
	return out, nil
}
