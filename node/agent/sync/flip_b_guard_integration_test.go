//go:build linux && integration

package sync

import (
	"fmt"
	"github.com/cilium/ebpf"
)

// These are exclusively config/trie fixtures. Explicit rejection prevents promotion.
func (m cut55ReplayLookupFault) BatchLookup(*ebpf.MapBatchCursor, interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
func (m cut55ReplayLookupFault) BatchUpdate(interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
func (m cut55ReplayLookupFault) BatchDelete(interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("config fixture used as rule mirror")
}
func (w *closeoutTrie) BatchLookup(*ebpf.MapBatchCursor, interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("trie fixture used as rule mirror")
}
func (w *closeoutTrie) BatchUpdate(interface{}, interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("trie fixture used as rule mirror")
}
func (w *closeoutTrie) BatchDelete(interface{}, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("trie fixture used as rule mirror")
}
