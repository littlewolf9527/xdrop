package bpf

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

// XDPMode is independent of the map/link pinning policy.
type XDPMode string

const (
	XDPAuto    XDPMode = "auto"
	XDPNative  XDPMode = "native"
	XDPGeneric XDPMode = "generic"
)

// XDPAttachment is the RTM_GETLINK startup snapshot. Attached uses the
// Linux UAPI XDP_ATTACHED_{NONE,DRV,SKB,HW,MULTI} values 0 through 4.
type XDPAttachment struct {
	Attached  uint8
	ProgID    uint32
	DriverID  uint32
	GenericID uint32
	OffloadID uint32
}

// XDPError keeps a stable diagnostic reason while retaining kernel errors.
type XDPError struct {
	Reason string
	Err    error
}

func (e *XDPError) Error() string { return e.Reason + ": " + e.Err.Error() }
func (e *XDPError) Unwrap() error { return e.Err }

func XDPFailureReason(err error) string {
	var e *XDPError
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func xdpError(reason string, err error) error { return &XDPError{Reason: reason, Err: err} }

// verifyXDPAttachment deliberately classifies BEFORE checking program identity.
// A matching per-mode ID never makes a multi attachment acceptable.
func verifyXDPAttachment(s XDPAttachment, expectedID func() (uint32, error)) (string, error) {
	var mode string
	switch s.Attached {
	case 0:
		return "", xdpError("xdp_none", fmt.Errorf("no XDP program attached"))
	case 1:
		mode = "native"
	case 2:
		mode = "generic"
	case 3:
		return "", xdpError("xdp_offload", fmt.Errorf("offload unsupported: HW_PROG_ID=%d", s.OffloadID))
	case 4:
		return "", xdpError("xdp_multi", fmt.Errorf("multiple attachments: DRV_PROG_ID=%d SKB_PROG_ID=%d HW_PROG_ID=%d", s.DriverID, s.GenericID, s.OffloadID))
	default:
		return "", xdpError("xdp_attached_unknown", fmt.Errorf("unknown IFLA_XDP_ATTACHED=%d", s.Attached))
	}
	if s.ProgID == 0 {
		return "", xdpError("xdp_prog_id_missing", fmt.Errorf("IFLA_XDP_PROG_ID is missing or zero"))
	}
	id, err := expectedID()
	if err != nil {
		return "", xdpError("xdp_prog_id_missing", fmt.Errorf("loaded program ID: %w", err))
	}
	if id == 0 {
		return "", xdpError("xdp_prog_id_missing", fmt.Errorf("loaded program ID is zero"))
	}
	if s.ProgID != id {
		return "", xdpError("xdp_prog_mismatch", fmt.Errorf("IFLA_XDP_PROG_ID=%d, loaded program ID=%d", s.ProgID, id))
	}
	return mode, nil
}

func readVerifiedXDP(prog *ebpf.Program, ifname string, ops linkOps) (string, error) {
	s, err := ops.ReadXDP(ifname)
	if err != nil {
		return "", xdpError("xdp_readback_failed", fmt.Errorf("RTM_GETLINK(%s): %w", ifname, err))
	}
	return verifyXDPAttachment(s, func() (uint32, error) { return ops.ProgramID(prog) })
}

func finishXDP(prog *ebpf.Program, ifname string, requested XDPMode, res *ResolvedXDPLink, ops linkOps) (*ResolvedXDPLink, error) {
	mode, err := readVerifiedXDP(prog, ifname, ops)
	if err == nil && requested != XDPAuto && mode != string(requested) {
		err = xdpError("xdp_mode_mismatch", fmt.Errorf("%s: requested=%s attached=%s", ifname, requested, mode))
	}
	if err != nil {
		return nil, errors.Join(err, res.ForceDetach())
	}
	res.AttachMode = mode
	warnXDPGeneric(ifname, requested, mode)
	return res, nil
}

func warnXDPGeneric(ifname string, requested XDPMode, attached string) {
	if requested == XDPAuto && attached == "generic" {
		log.Printf("[bpf] WARN: %s requested=auto attached=generic，性能约低一个量级", ifname)
	}
}

// ReadXDPAttachment returns the current kernel attachment, regardless of owner.
func ReadXDPAttachment(ifname string) (XDPAttachment, error) {
	return readXDPAttachment(ifname)
}
