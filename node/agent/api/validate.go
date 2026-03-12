// XDrop Agent - Rule field validation and parsing
package api

import "fmt"

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
