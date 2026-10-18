package api

import "github.com/cilium/ebpf"

type configPublishMap interface {
	Lookup(interface{}, interface{}) error
	Update(interface{}, interface{}, ebpf.MapUpdateFlags) error
}
type configPublishTableSet struct{ shadow, active, selector configPublishMap }

func (h *Handlers) configPublishTables() (configPublishMap, configPublishMap, configPublishMap) {
	if h.configPublishFixture != nil {
		f := h.configPublishFixture
		return f.shadow, f.active, f.selector
	}
	return h.shadowMap(), h.activeMap(), h.activeConfig
}
