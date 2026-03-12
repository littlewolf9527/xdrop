// XDrop Agent - 34-combo type classification for bitmap optimization
package api

// Combo type constants (must match xdrop.h)
const (
	ComboExact5Tuple          = 0  // src_ip + dst_ip + src_port + dst_port + protocol
	ComboWildcardSrcIP        = 1  // dst_ip + src_port + dst_port + protocol
	ComboWildcardSrcIPPort    = 2  // dst_ip + dst_port + protocol
	ComboDstIPProto           = 3  // dst_ip + protocol
	ComboDstIPOnly            = 4  // dst_ip only
	ComboProtoOnly            = 5  // protocol only
	ComboSrcPortOnly          = 6  // src_port only
	ComboDstPortOnly          = 7  // dst_port only
	ComboSrcIPOnly            = 8  // src_ip only
	ComboSrcIPProto           = 9  // src_ip + protocol
	ComboSrcDstIP             = 10 // src_ip + dst_ip
	ComboSrcIPDstPort         = 11 // src_ip + dst_port
	ComboDstIPDstPort         = 12 // dst_ip + dst_port
	ComboSrcDstIPProto        = 13 // src_ip + dst_ip + protocol
	ComboSrcIPDstPortProto    = 14 // src_ip + dst_port + protocol
	ComboSrcPortProto         = 15 // src_port + protocol
	ComboDstPortProto         = 16 // dst_port + protocol
	ComboSrcIPSrcPort         = 17 // src_ip + src_port
	ComboSrcIPSrcPortProto    = 18 // src_ip + src_port + protocol
	// Note: combo 19 was removed (duplicate of ComboDstIPProto)
	ComboDstIPDstPortProto    = 20 // dst_ip + dst_port + protocol
	ComboSrcDstIPDstPort      = 21 // src_ip + dst_ip + dst_port
	ComboSrcDstIPDstPortProto = 22 // src_ip + dst_ip + dst_port + protocol
	ComboSrcIPPorts           = 23 // src_ip + src_port + dst_port
	ComboSrcIPPortsProto      = 24 // src_ip + src_port + dst_port + protocol
	ComboDstIPSrcPort         = 25 // dst_ip + src_port
	ComboDstIPSrcPortProto    = 26 // dst_ip + src_port + protocol
	ComboPortsOnly            = 27 // src_port + dst_port
	ComboPortsProto           = 28 // src_port + dst_port + protocol
	ComboSrcDstIPSrcPort      = 29 // src_ip + dst_ip + src_port
	ComboSrcDstIPSrcPortProto = 30 // src_ip + dst_ip + src_port + protocol
	ComboDstIPPorts           = 31 // dst_ip + src_port + dst_port
	ComboDstIPPortsProto      = 32 // dst_ip + src_port + dst_port + protocol
	ComboAllExceptProto       = 33 // src_ip + dst_ip + src_port + dst_port
)

// isZeroIP checks if an IP address is all zeros
func isZeroIP(ip IPAddr) bool {
	for _, b := range ip {
		if b != 0 {
			return false
		}
	}
	return true
}

// getComboType determines the combo type based on which fields are set
func getComboType(key RuleKey) int {
	hasSrcIP := !isZeroIP(key.SrcIP)
	hasDstIP := !isZeroIP(key.DstIP)
	hasSrcPort := key.SrcPort != 0
	hasDstPort := key.DstPort != 0
	hasProto := key.Protocol != 0

	// Map field combinations to combo type
	switch {
	case hasSrcIP && hasDstIP && hasSrcPort && hasDstPort && hasProto:
		return ComboExact5Tuple
	case !hasSrcIP && hasDstIP && hasSrcPort && hasDstPort && hasProto:
		return ComboWildcardSrcIP
	case !hasSrcIP && hasDstIP && !hasSrcPort && hasDstPort && hasProto:
		return ComboWildcardSrcIPPort
	case !hasSrcIP && hasDstIP && !hasSrcPort && !hasDstPort && hasProto:
		return ComboDstIPProto
	case !hasSrcIP && hasDstIP && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboDstIPOnly
	case !hasSrcIP && !hasDstIP && !hasSrcPort && !hasDstPort && hasProto:
		return ComboProtoOnly
	case !hasSrcIP && !hasDstIP && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcPortOnly
	case !hasSrcIP && !hasDstIP && !hasSrcPort && hasDstPort && !hasProto:
		return ComboDstPortOnly
	case hasSrcIP && !hasDstIP && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcIPOnly
	case hasSrcIP && !hasDstIP && !hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcIPProto
	case hasSrcIP && hasDstIP && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcDstIP
	case hasSrcIP && !hasDstIP && !hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcIPDstPort
	case !hasSrcIP && hasDstIP && !hasSrcPort && hasDstPort && !hasProto:
		return ComboDstIPDstPort
	case hasSrcIP && hasDstIP && !hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcDstIPProto
	case hasSrcIP && !hasDstIP && !hasSrcPort && hasDstPort && hasProto:
		return ComboSrcIPDstPortProto
	case !hasSrcIP && !hasDstIP && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcPortProto
	case !hasSrcIP && !hasDstIP && !hasSrcPort && hasDstPort && hasProto:
		return ComboDstPortProto
	case hasSrcIP && !hasDstIP && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcIPSrcPort
	case hasSrcIP && !hasDstIP && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcIPSrcPortProto
	case !hasSrcIP && hasDstIP && !hasSrcPort && hasDstPort && hasProto:
		return ComboDstIPDstPortProto
	case hasSrcIP && hasDstIP && !hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcDstIPDstPort
	case hasSrcIP && hasDstIP && !hasSrcPort && hasDstPort && hasProto:
		return ComboSrcDstIPDstPortProto
	case hasSrcIP && !hasDstIP && hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcIPPorts
	case hasSrcIP && !hasDstIP && hasSrcPort && hasDstPort && hasProto:
		return ComboSrcIPPortsProto
	case !hasSrcIP && hasDstIP && hasSrcPort && !hasDstPort && !hasProto:
		return ComboDstIPSrcPort
	case !hasSrcIP && hasDstIP && hasSrcPort && !hasDstPort && hasProto:
		return ComboDstIPSrcPortProto
	case !hasSrcIP && !hasDstIP && hasSrcPort && hasDstPort && !hasProto:
		return ComboPortsOnly
	case !hasSrcIP && !hasDstIP && hasSrcPort && hasDstPort && hasProto:
		return ComboPortsProto
	case hasSrcIP && hasDstIP && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcDstIPSrcPort
	case hasSrcIP && hasDstIP && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcDstIPSrcPortProto
	case !hasSrcIP && hasDstIP && hasSrcPort && hasDstPort && !hasProto:
		return ComboDstIPPorts
	case !hasSrcIP && hasDstIP && hasSrcPort && hasDstPort && hasProto:
		return ComboDstIPPortsProto
	case hasSrcIP && hasDstIP && hasSrcPort && hasDstPort && !hasProto:
		return ComboAllExceptProto
	default:
		return -1 // Unknown combination
	}
}

// getCIDRComboType determines combo type for a CIDR rule key (same logic as getComboType but uses IDs)
func getCIDRComboType(key CIDRRuleKey) int {
	hasSrcID := key.SrcID != 0
	hasDstID := key.DstID != 0
	hasSrcPort := key.SrcPort != 0
	hasDstPort := key.DstPort != 0
	hasProto := key.Protocol != 0

	switch {
	case hasSrcID && hasDstID && hasSrcPort && hasDstPort && hasProto:
		return ComboExact5Tuple
	case !hasSrcID && hasDstID && hasSrcPort && hasDstPort && hasProto:
		return ComboWildcardSrcIP
	case !hasSrcID && hasDstID && !hasSrcPort && hasDstPort && hasProto:
		return ComboWildcardSrcIPPort
	case !hasSrcID && hasDstID && !hasSrcPort && !hasDstPort && hasProto:
		return ComboDstIPProto
	case !hasSrcID && hasDstID && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboDstIPOnly
	case !hasSrcID && !hasDstID && !hasSrcPort && !hasDstPort && hasProto:
		return ComboProtoOnly
	case !hasSrcID && !hasDstID && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcPortOnly
	case !hasSrcID && !hasDstID && !hasSrcPort && hasDstPort && !hasProto:
		return ComboDstPortOnly
	case hasSrcID && !hasDstID && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcIPOnly
	case hasSrcID && !hasDstID && !hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcIPProto
	case hasSrcID && hasDstID && !hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcDstIP
	case hasSrcID && !hasDstID && !hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcIPDstPort
	case !hasSrcID && hasDstID && !hasSrcPort && hasDstPort && !hasProto:
		return ComboDstIPDstPort
	case hasSrcID && hasDstID && !hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcDstIPProto
	case hasSrcID && !hasDstID && !hasSrcPort && hasDstPort && hasProto:
		return ComboSrcIPDstPortProto
	case !hasSrcID && !hasDstID && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcPortProto
	case !hasSrcID && !hasDstID && !hasSrcPort && hasDstPort && hasProto:
		return ComboDstPortProto
	case hasSrcID && !hasDstID && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcIPSrcPort
	case hasSrcID && !hasDstID && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcIPSrcPortProto
	case !hasSrcID && hasDstID && !hasSrcPort && hasDstPort && hasProto:
		return ComboDstIPDstPortProto
	case hasSrcID && hasDstID && !hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcDstIPDstPort
	case hasSrcID && hasDstID && !hasSrcPort && hasDstPort && hasProto:
		return ComboSrcDstIPDstPortProto
	case hasSrcID && !hasDstID && hasSrcPort && hasDstPort && !hasProto:
		return ComboSrcIPPorts
	case hasSrcID && !hasDstID && hasSrcPort && hasDstPort && hasProto:
		return ComboSrcIPPortsProto
	case !hasSrcID && hasDstID && hasSrcPort && !hasDstPort && !hasProto:
		return ComboDstIPSrcPort
	case !hasSrcID && hasDstID && hasSrcPort && !hasDstPort && hasProto:
		return ComboDstIPSrcPortProto
	case !hasSrcID && !hasDstID && hasSrcPort && hasDstPort && !hasProto:
		return ComboPortsOnly
	case !hasSrcID && !hasDstID && hasSrcPort && hasDstPort && hasProto:
		return ComboPortsProto
	case hasSrcID && hasDstID && hasSrcPort && !hasDstPort && !hasProto:
		return ComboSrcDstIPSrcPort
	case hasSrcID && hasDstID && hasSrcPort && !hasDstPort && hasProto:
		return ComboSrcDstIPSrcPortProto
	case !hasSrcID && hasDstID && hasSrcPort && hasDstPort && !hasProto:
		return ComboDstIPPorts
	case !hasSrcID && hasDstID && hasSrcPort && hasDstPort && hasProto:
		return ComboDstIPPortsProto
	case hasSrcID && hasDstID && hasSrcPort && hasDstPort && !hasProto:
		return ComboAllExceptProto
	default:
		return -1
	}
}
