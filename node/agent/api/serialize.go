// XDrop Agent - BPF map key/value serialization
package api

import (
	"encoding/binary"
	"net"
)

// cidrRuleKeyToBytes converts CIDRRuleKey to 16-byte slice for BPF map
func cidrRuleKeyToBytes(k CIDRRuleKey) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], k.SrcID)
	binary.LittleEndian.PutUint32(b[4:], k.DstID)
	binary.LittleEndian.PutUint16(b[8:], k.SrcPort)
	binary.LittleEndian.PutUint16(b[10:], k.DstPort)
	b[12] = k.Protocol
	// b[13:16] = pad (zeros)
	return b
}

// ruleKeyToBytes converts RuleKey to 40-byte slice for BPF map
func ruleKeyToBytes(k RuleKey) []byte {
	b := make([]byte, 40)
	// Copy src_ip (16 bytes)
	copy(b[0:16], k.SrcIP[:])
	// Copy dst_ip (16 bytes)
	copy(b[16:32], k.DstIP[:])
	// Ports (in network byte order via htons)
	binary.LittleEndian.PutUint16(b[32:], k.SrcPort)
	binary.LittleEndian.PutUint16(b[34:], k.DstPort)
	// Protocol and padding
	b[36] = k.Protocol
	return b
}

func ruleValueToBytes(v RuleValue) []byte {
	b := make([]byte, 32)
	b[0] = v.Action
	b[1] = v.TcpFlagsMask
	b[2] = v.TcpFlagsValue
	b[3] = v.MatchAnomaly // v2.6 Phase 4: previously pad
	binary.LittleEndian.PutUint32(b[4:], v.RateLimit)
	binary.LittleEndian.PutUint64(b[8:], v.MatchCount)
	binary.LittleEndian.PutUint64(b[16:], v.DropCount)
	binary.LittleEndian.PutUint16(b[24:], v.PktLenMin)
	binary.LittleEndian.PutUint16(b[26:], v.PktLenMax)
	// b[28:32] is pad2 (zeros, reserved for future anomaly widening)
	return b
}

// ipToIPAddr converts net.IP to IPAddr (IPv4-mapped or native IPv6)
func ipToIPAddr(ip net.IP) IPAddr {
	var addr IPAddr

	// Check if it's IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6: ::ffff:x.x.x.x
		addr[10] = 0xff
		addr[11] = 0xff
		copy(addr[12:], ip4)
	} else if ip16 := ip.To16(); ip16 != nil {
		// Native IPv6
		copy(addr[:], ip16)
	}

	return addr
}

// ipAddrToString converts IPAddr to string representation
func ipAddrToString(addr IPAddr) string {
	// Check if all zeros (wildcard)
	allZero := true
	for _, b := range addr {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}

	// Check if IPv4-mapped
	isV4Mapped := true
	for i := 0; i < 10; i++ {
		if addr[i] != 0 {
			isV4Mapped = false
			break
		}
	}
	if isV4Mapped && addr[10] == 0xff && addr[11] == 0xff {
		// Return as IPv4
		return net.IP(addr[12:16]).String()
	}

	// Return as IPv6
	return net.IP(addr[:]).String()
}
