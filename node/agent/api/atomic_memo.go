package api

import (
	"fmt"
	"net"
)

// atomicMemo belongs to one DoAtomicSync call, including failed preparations.
type atomicMemo struct {
	cidrs    map[string]atomicCIDRParse
	prepared map[int]atomicPreparation
}
type atomicCIDRParse struct {
	ip           net.IP
	network      *net.IPNet
	err          error
	normalized   string
	normalizeErr error
}
type atomicPreparation struct {
	rule atomicPreparedRule
	err  error
}

func firstMemo(memos []*atomicMemo) *atomicMemo {
	if len(memos) > 0 {
		return memos[0]
	}
	return nil
}
func (m *atomicMemo) parse(s string) atomicCIDRParse {
	if m != nil {
		if p, ok := m.cidrs[s]; ok {
			return p
		}
	}
	ip, network, err := net.ParseCIDR(s)
	p := atomicCIDRParse{ip: ip, network: network, err: err}
	if err != nil {
		p.normalizeErr = fmt.Errorf("invalid CIDR: %s", s)
	} else {
		p.normalized = network.String()
	}
	if m != nil {
		m.cidrs[s] = p
	}
	return p
}
func (m *atomicMemo) normalize(s string) (string, error) {
	p := m.parse(s)
	return p.normalized, p.normalizeErr
}
func (h *Handlers) prepareAtomicAt(r Rule, index int, m *atomicMemo) (atomicPreparedRule, error) {
	if m != nil {
		if p, ok := m.prepared[index]; ok {
			return p.rule, p.err
		}
	}
	p, err := h.prepareAtomicRule(r, m)
	if m != nil {
		m.prepared[index] = atomicPreparation{p, err}
	}
	return p, err
}
