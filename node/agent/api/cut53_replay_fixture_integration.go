//go:build linux && integration

package api

import "github.com/cilium/ebpf"

// ReplayPinnedStartupForCut53 exposes the real startup operation to the common
// cross-version replay driver via reflection. It is absent from normal builds; the replay driver no longer supports trees that lack it.
func (*Handlers) ReplayPinnedStartupForCut53(main, gate *ebpf.Collection) error {
	return PreparePinnedStartup(main, gate)
}
