// XDrop Agent - Rule field validation and parsing
package api

import (
	"fmt"
	"strings"
)

func htons(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}

func ntohs(n uint16) uint16 {
	return htons(n)
}

func parseProtocol(s string) uint8 {
	switch s {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	case "icmp":
		return ProtoICMP
	case "icmpv6":
		return ProtoICMPv6
	default:
		return ProtoAll
	}
}

func protocolToString(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	default:
		return "all"
	}
}

func parseAction(s string) (uint8, error) {
	switch s {
	case "drop", "":
		return ActionDrop, nil
	case "rate_limit":
		return ActionRateLimit, nil
	default:
		return 0, fmt.Errorf("invalid action: %q (valid: drop, rate_limit)", s)
	}
}

// TCP flag bit positions (in the flags byte: CWR ECE URG ACK PSH RST SYN FIN)
var tcpFlagBits = map[string]uint8{
	"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
	"ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}

// parseTcpFlags parses a human-readable TCP flags string into mask and value.
// Format: "SYN,!ACK" means SYN=1 and ACK=0. Returns (mask, value, error).
// Empty string returns (0, 0, nil) meaning no flags check.
func parseTcpFlags(s string) (uint8, uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}

	var mask, value uint8
	seen := make(map[string]bool)

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue // ignore empty segments
		}

		negate := false
		name := strings.ToUpper(part)
		if strings.HasPrefix(name, "!") {
			negate = true
			name = name[1:]
		}

		bit, ok := tcpFlagBits[name]
		if !ok {
			return 0, 0, fmt.Errorf("unknown TCP flag %q; valid: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR", part)
		}

		// Check for contradiction BEFORE dedup: same flag both set and negated
		if negate && seen[name] {
			return 0, 0, fmt.Errorf("contradictory TCP flags: both %s and !%s specified", name, name)
		}
		if !negate && seen["!"+name] {
			return 0, 0, fmt.Errorf("contradictory TCP flags: both %s and !%s specified", name, name)
		}
		key := name
		if negate {
			key = "!" + name
		}
		if seen[key] {
			continue // silently deduplicate
		}
		seen[key] = true

		mask |= bit
		if !negate {
			value |= bit
		}
	}

	return mask, value, nil
}

// tcpFlagsToString converts mask/value back to human-readable string.
func tcpFlagsToString(mask, value uint8) string {
	if mask == 0 {
		return ""
	}
	var parts []string
	for _, name := range []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"} {
		bit := tcpFlagBits[name]
		if mask&bit == 0 {
			continue
		}
		if value&bit != 0 {
			parts = append(parts, name)
		} else {
			parts = append(parts, "!"+name)
		}
	}
	return strings.Join(parts, ",")
}

// validateRule checks if the rule is valid
// Returns error if it's a pure-length rule (no 5-tuple fields) or has invalid length range
func validateRule(srcIP, dstIP, protocol string, srcPort, dstPort, pktLenMin, pktLenMax uint16) error {
	hasLengthFilter := pktLenMin > 0 || pktLenMax > 0
	has5Tuple := srcIP != "" || dstIP != "" ||
		srcPort != 0 || dstPort != 0 ||
		(protocol != "" && protocol != "all")

	if hasLengthFilter && !has5Tuple {
		return fmt.Errorf("pure length rules not allowed: must specify at least one of src_ip, dst_ip, src_port, dst_port, or protocol")
	}

	if pktLenMin > 0 && pktLenMax > 0 && pktLenMin > pktLenMax {
		return fmt.Errorf("invalid length range: min (%d) > max (%d)", pktLenMin, pktLenMax)
	}

	return nil
}
