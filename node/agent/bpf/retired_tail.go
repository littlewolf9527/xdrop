package bpf

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
)

type tailSlotMap interface {
	Delete(key interface{}) error
}

// ClearRetiredTailSlot runs on every kernel, before attaching the new chain.
// An empty PROG_ARRAY slot returns ENOENT; every other error closes startup.
func ClearRetiredTailSlot(table tailSlotMap) error {
	if err := table.Delete(uint32(0)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("clear prog_tail_map slot 0: %w", err)
	}
	return nil
}
