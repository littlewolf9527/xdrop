// decoder.go — input-side decoder syntactic sugar (v2.6 Phase 2 / Phase 4).
//
// The Controller accepts `decoder=tcp_ack` style input from xSight v1.3 clients
// and normalizes it into the underlying rule predicate before storage. The
// persisted rule uses protocol / tcp_flags (and in Phase 4, match_anomaly).
// GET responses never expose a `decoder` field — clients reading rules always
// see the underlying fields.
//
// Ownership: handlers stay thin and call normalizeDecoder first thing; they
// DO NOT implement the expansion themselves. This keeps drift bounded to one
// file and matches the v2.6 audit decision (§7.4.1 / §5.5).
package service

import (
	"fmt"
	"net"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// Known decoder strings accepted on input. Expand this map when adding new
// sugar. Values encode "what underlying fields this decoder sets" — the
// expander reads the entry and applies it.
type decoderSpec struct {
	Protocol string
	TcpFlags string // "" means don't set tcp_flags (for non-TCP-flag decoders)
	// Phase 4 extensions (match_anomaly bits) land here when added. Not used
	// in Phase 2 Tier-1 sugar.
	AnomalyBits uint8 // 0 = no anomaly field; non-zero set during Phase 4.
}

// anomaly bits (v2.6 Phase 4 — kept adjacent to the sugar spec so decoder
// definitions live in one place).
const (
	AnomalyBadFragment uint8 = 0x01
	AnomalyInvalid     uint8 = 0x02
)

var knownDecoders = map[string]decoderSpec{
	// Phase 2 Tier 1 — TCP flag specializations. Semantics must match xSight
	// DECODER_SWITCH (see xsight/node/bpf/xsight.c lines 34, 38, 42):
	//   tcp_ack = ACK set AND SYN clear (NOT just "ACK set"; NOT pure ACK)
	//   tcp_rst = RST set (regardless of ACK)
	//   tcp_fin = FIN set (regardless of ACK)
	"tcp_ack": {Protocol: "tcp", TcpFlags: "ACK,!SYN"},
	"tcp_rst": {Protocol: "tcp", TcpFlags: "RST"},
	"tcp_fin": {Protocol: "tcp", TcpFlags: "FIN"},

	// Phase 4 Tier 3 — anomaly decoders. Expand to protocol (caller-provided
	// stays if already set; otherwise empty = "all") + AnomalyBits for
	// downstream match_anomaly field. TcpFlags stays empty.
	"bad_fragment": {AnomalyBits: AnomalyBadFragment},
	"invalid":      {AnomalyBits: AnomalyInvalid},

	// Tier 2 (gre/esp/igmp) is NOT a decoder sugar — users set protocol
	// directly. Adding those as decoders would be noise. See proposal §1.
}

// normalizeDecoder mutates req in place, expanding the Decoder field into
// underlying predicate fields. Returns an error when the input is invalid:
//   - unknown decoder string
//   - decoder set together with explicit protocol
//   - decoder set together with explicit tcp_flags
//
// Empty Decoder is a no-op (allows callers to always invoke this helper).
//
// Calls Create path for all callers; Update path uses
// `normalizeDecoderForUpdate` instead (it skips the "anomaly decoder
// requires explicit target" gate since the target is already in the
// existing rule).
func normalizeDecoder(req *model.RuleRequest) error {
	return normalizeDecoderInternal(req, true /* requireExplicitTarget */)
}

// normalizeDecoderForUpdate is the Update-path variant: same expansion
// + IPv6 scope guard as Create, but relaxes the "anomaly decoder
// requires explicit target" gate because the existing rule already has
// a tuple. Caller supplies the existing rule's target fields as
// hasExistingTarget so the IPv6 scope guard can still fire (would-be
// IPv6 target on existing rule still gets rejected for bad_fragment).
func normalizeDecoderForUpdate(req *model.RuleRequest, existing *model.Rule) error {
	// If request doesn't name an explicit target, seed one from existing
	// rule so the IPv6 scope guard inside normalizeDecoder sees the real
	// target. This is purely for the scope-guard check; req fields are
	// restored afterward so Update's field-by-field merge logic isn't
	// perturbed.
	if req.DstIP == "" && req.SrcIP == "" && req.DstCIDR == "" && req.SrcCIDR == "" {
		// Seed req.DstIP / DstCIDR / etc. from existing, run decoder
		// expansion, then restore.
		saved := struct {
			DstIP, SrcIP, DstCIDR, SrcCIDR string
		}{req.DstIP, req.SrcIP, req.DstCIDR, req.SrcCIDR}
		req.DstIP = existing.DstIP
		req.SrcIP = existing.SrcIP
		req.DstCIDR = existing.DstCIDR
		req.SrcCIDR = existing.SrcCIDR
		err := normalizeDecoderInternal(req, false /* don't require explicit — we seeded */)
		// Always restore; even on error, the caller might want the original.
		req.DstIP, req.SrcIP, req.DstCIDR, req.SrcCIDR = saved.DstIP, saved.SrcIP, saved.DstCIDR, saved.SrcCIDR
		return err
	}
	// User provided an explicit target in the PUT body — use normal path.
	return normalizeDecoderInternal(req, true)
}

func normalizeDecoderInternal(req *model.RuleRequest, requireExplicitTarget bool) error {
	if req.Decoder == "" {
		return nil
	}

	spec, ok := knownDecoders[req.Decoder]
	if !ok {
		return fmt.Errorf("unknown decoder %q: allowed values are tcp_ack, tcp_rst, tcp_fin, bad_fragment, invalid", req.Decoder)
	}

	// Mutual exclusion with explicit predicate fields. Even when the explicit
	// input happens to agree with the expansion (e.g. decoder=tcp_ack +
	// tcp_flags="ACK,!SYN"), we reject — this prevents silent drift when the
	// decoder semantics change.
	if req.Protocol != "" {
		return fmt.Errorf("decoder %q conflicts with explicit protocol %q: set one or the other",
			req.Decoder, req.Protocol)
	}
	if req.TcpFlags != nil && *req.TcpFlags != "" {
		return fmt.Errorf("decoder %q conflicts with explicit tcp_flags %q: set one or the other",
			req.Decoder, *req.TcpFlags)
	}
	if req.MatchAnomaly != 0 {
		return fmt.Errorf("decoder %q conflicts with explicit match_anomaly=%d: set one or the other",
			req.Decoder, req.MatchAnomaly)
	}

	// Apply expansion.
	if spec.Protocol != "" {
		req.Protocol = spec.Protocol
	}
	if spec.TcpFlags != "" {
		s := spec.TcpFlags
		req.TcpFlags = &s
	}
	if spec.AnomalyBits != 0 {
		// v2.6.1 B5 data-plane scope: anomaly rules currently support only
		// ACTION_DROP. The cross-program rate_limit token-bucket sharing via
		// rl_states map has race risks (main program writes rate state from
		// one program path while xdp_anomaly_verify would write from a
		// different path — without cross-program coordination the tokens
		// decrement twice). Documented in v2.6.1-deploy-summary.md as a
		// known simplification. Previously Controller silently accepted
		// `action=rate_limit` and anomaly_verify mapped it to XDP_DROP;
		// codex round 9 audit P1.1 flagged the silent contract mismatch.
		// Reject up front until real cross-program rate_limit lands
		// (candidate work in a future release).
		if req.Action == "rate_limit" {
			return fmt.Errorf(
				"anomaly decoder %q does not support action=rate_limit in v2.6.1 (anomaly rules are drop-only; real rate_limit support deferred — see proposal §7.8.4 and v2.6.1-deploy-summary.md)",
				req.Decoder)
		}

		// IPv6 scope guard (proposal §7.4.1). v1.3 xsight.c only sets
		// is_bad_fragment for IPv4; silently accepting an IPv6-targeted
		// bad_fragment rule creates a rule that matches nothing (match_count
		// stays 0) while the caller thinks mitigation is active. Reject up
		// front with a stable diagnosis string — xdrop-side scripts grep
		// this substring, so changing it is a contract break.
		//
		// `invalid` decoder is NOT rejected for IPv6: the TCP doff check
		// fires naturally on direct-TCP v6 packets (see proposal P4-UT-14/15
		// and LT-D-4-11).
		if spec.AnomalyBits == AnomalyBadFragment {
			if err := rejectIPv6AnomalyTarget(req, req.Decoder); err != nil {
				return err
			}
		}
		// Empty-target guard: any anomaly decoder with no 5-tuple anchor
		// describes a rule whose "scope" is literally every packet. That's
		// almost never what the caller meant and silently creates a rule
		// that drops all fragments / invalid packets on the node — wide
		// blast radius. Reject with a stable diagnosis.
		//
		// Update path sets requireExplicitTarget=false since the existing
		// rule already has a tuple; the caller (normalizeDecoderForUpdate)
		// seeded req.DstIP etc. so the IPv6 scope guard above still works.
		if requireExplicitTarget && !hasExplicitTarget(req) {
			return fmt.Errorf("anomaly decoder requires explicit dst_ip / dst_cidr / src_ip / src_cidr")
		}
		req.MatchAnomaly = int(spec.AnomalyBits)
	}

	// Clear the Decoder field so downstream validation doesn't see a residual
	// value that could be accidentally persisted.
	req.Decoder = ""
	return nil
}

// hasExplicitTarget is true when req specifies any 5-tuple anchor that would
// bound the anomaly rule's scope. Ports alone (without IP/CIDR) don't count —
// a bare `dst_port=80` anomaly rule is still a near-universal match.
func hasExplicitTarget(req *model.RuleRequest) bool {
	return req.DstIP != "" || req.DstCIDR != "" || req.SrcIP != "" || req.SrcCIDR != ""
}

// isIPv6String reports whether s parses as an IPv6 address.
func isIPv6String(s string) bool {
	if s == "" {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// isIPv6CIDR reports whether the CIDR notation carries an IPv6 prefix.
func isIPv6CIDR(s string) bool {
	if s == "" {
		return false
	}
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return ip.To4() == nil
}

// rejectIPv6AnomalyTarget returns 400 when a bad_fragment rule's target is
// IPv6. v1.3 does not detect IPv6 bad_fragment in BPF; accepting the rule
// would be a silent no-op.
//
// IMPORTANT: the diagnosis string below is a contract. Ops scripts grep for
// "not supported for IPv6 target in v1.3" and "deferred to v1.4" — do NOT
// change those phrases without updating rule_service_test.go (P4-UT-44) and
// any callers that pattern-match the response body.
func rejectIPv6AnomalyTarget(req *model.RuleRequest, decoderName string) error {
	v6 := isIPv6String(req.DstIP) || isIPv6String(req.SrcIP) ||
		isIPv6CIDR(req.DstCIDR) || isIPv6CIDR(req.SrcCIDR)
	if !v6 {
		return nil
	}
	return fmt.Errorf(
		"decoder %q not supported for IPv6 target in v1.3 "+
			"(IPv6 fragment detection deferred to v1.4); "+
			"use BGP null-route or rate-limit instead",
		decoderName)
}
