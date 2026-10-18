package api

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// StartupMap permits key-only iteration, including PERCPU_HASH values.
type StartupMap interface {
	KeySize() uint32
	NextKey(interface{}, interface{}) error
	Delete(interface{}) error
}

// StrictClearAndRecount fails on any enumeration/delete error or surviving key.
// It must only run after the caller has stopped this table's producers.
func StrictClearAndRecount(m StartupMap) error {
	if m == nil {
		return fmt.Errorf("map unavailable")
	}
	var cursor interface{}
	var keys [][]byte
	for {
		key := make([]byte, m.KeySize())
		if err := m.NextKey(cursor, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return fmt.Errorf("enumerate: %w", err)
		}
		keys = append(keys, key)
		cursor = key
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
	}
	key := make([]byte, m.KeySize())
	if err := m.NextKey(nil, &key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("recount: %w", err)
	}
	return fmt.Errorf("recount: nonempty map")
}
