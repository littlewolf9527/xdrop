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
	p, _ := parseProtocolStrict(s)
	return p
}

// parseProtocolStrict returns (protocol, error). Unknown strings return an error
// instead of silently mapping to ProtoAll, preventing whitelist combo broadening.
func parseProtocolStrict(s string) (uint8, error) {
	switch s {
	case "", "all":
		return ProtoAll, nil
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "icmp":
		return ProtoICMP, nil
	case "icmpv6":
		return ProtoICMPv6, nil
	case "igmp":
		return ProtoIGMP, nil
	case "gre":
		return ProtoGRE, nil
	case "esp":
		return ProtoESP, nil
	default:
		return 0, fmt.Errorf("unknown protocol %q; supported: tcp, udp, icmp, icmpv6, igmp, gre, esp, all", s)
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
	case ProtoIGMP:
		return "igmp"
	case ProtoGRE:
		return "gre"
	case ProtoESP:
		return "esp"
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

	// B-10 (rev11 codex round 9 P2): Node-side portless+port guard. The BPF
	// data plane (xdrop.c parse_l4) only fills key.src_port/dst_port for
	// PROTO_TCP and PROTO_UDP — every other protocol leaves the key ports
	// at 0. Storing a rule with src_port=500 + protocol=gre would create a
	// permanent BPF lookup miss (rule key port=500 ≠ packet key port=0).
	// Reject at every Node write entry — direct API, batch, FromSync,
	// AtomicSync — defending against direct-Node clients and any Controller
	// regression. Mirrors Controller's validatePortProtocolCompat.
	if err := validatePortProtocolCompatNode(protocol, srcPort, dstPort); err != nil {
		return err
	}

	return nil
}

// portlessProtocolsNode mirrors Controller's portlessProtocols set. ICMP /
// ICMPv6 / IGMP / GRE / ESP do not carry L4 ports.
var portlessProtocolsNode = map[string]bool{
	"icmp":   true,
	"icmpv6": true,
	"igmp":   true,
	"gre":    true,
	"esp":    true,
}

// validatePortProtocolCompatNode is the Node-side mirror of Controller's
// validatePortProtocolCompat. Empty protocol and "all" are wildcard semantics
// that may match TCP/UDP packets, so port stays valid; only the explicit
// portless set is rejected when ports are non-zero.
//
// rev12 (codex round 11 P3): normalize via strings.ToLower so direct-Node
// clients sending mixed/upper case (e.g. "GRE") still hit the guard.
// Controller's validateProtocol enforces lowercase before sync, but Node
// is meant to be a strong direct defense — this closes the gap where
// `parseProtocol("GRE")` would fall through to ProtoAll and bypass B-10.
func validatePortProtocolCompatNode(protocol string, srcPort, dstPort uint16) error {
	if !portlessProtocolsNode[strings.ToLower(protocol)] {
		return nil
	}
	if srcPort == 0 && dstPort == 0 {
		return nil
	}
	return fmt.Errorf(
		"protocol=%s does not carry ports (src_port/dst_port must be 0); got src_port=%d dst_port=%d",
		protocol, srcPort, dstPort)
}
