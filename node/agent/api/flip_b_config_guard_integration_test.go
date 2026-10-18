//go:build linux && integration

package api

import (
	"fmt"
	"github.com/cilium/ebpf"
)

// This wrapper is only a configPublishMap; reject accidental rule-batch routing.
func (m *cut53KernelConfigMap) BatchLookup(*ebpf.MapBatchCursor, interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
func (m *cut53KernelConfigMap) BatchUpdate(interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
func (m *cut53KernelConfigMap) BatchDelete(interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
