package rules

import "github.com/littlewolf9527/xdrop/controller/core/store"

// SnapshotTestHook is installed before starting test workers and removed only
// after they stop. Production leaves it nil. <kind> runs under the write lock
// after drain, before the snapshot is pinned; <kind>_pinned runs after the lock
// is released, before rows are read. The callback must not call the service
// while the lock is held.
var SnapshotTestHook func(*Service, string) error

func (s *Service) pinned(kind string, inLock func() bool, read func(store.Queryer) error) (ran bool, e *Error) {
	snap, err := s.db.BeginSnapshot()
	if err != nil {
		return false, internal(err)
	}
	defer snap.Close()
	s.mu.Lock()
	ran = inLock()
	if !ran {
		s.mu.Unlock()
		return false, nil
	}
	if SnapshotTestHook != nil {
		if err := SnapshotTestHook(s, kind); err != nil {
			s.mu.Unlock()
			return ran, internal(err)
		}
	}
	if err := snap.Pin(); err != nil {
		s.mu.Unlock()
		return ran, internal(err)
	}
	s.mu.Unlock()
	if SnapshotTestHook != nil {
		if err := SnapshotTestHook(s, kind+"_pinned"); err != nil {
			return ran, internal(err)
		}
	}
	if err := read(snap.Tx); err != nil {
		return ran, internal(err)
	}
	return ran, nil
}

// SnapshotGroups keeps draining notifications and reading their contents inside
// the same write exclusion boundary. The callback must not call the service.
func (s *Service) SnapshotGroups(drain func() []string) (keys []string, groups map[string][]store.Rule, e *Error) {
	_, e = s.pinned("groups", func() bool { keys = drain(); return true }, func(tx store.Queryer) error {
		var err error
		groups, err = store.EnabledByGroups(tx, keys)
		return err
	})
	if e != nil {
		return keys, nil, e
	}
	return keys, groups, nil
}

func (s *Service) SnapshotEnabled(drain func()) ([]store.NodeRow, *Error) {
	var rows []store.NodeRow
	_, e := s.pinned("enabled", func() bool { drain(); return true }, func(tx store.Queryer) error {
		var err error
		rows, err = store.EnabledForNode(tx)
		if err == nil && SnapshotTestHook != nil {
			err = SnapshotTestHook(s, "enabled_done")
		}
		return err
	})
	if e != nil {
		return nil, e
	}
	return rows, nil
}

func (s *Service) SnapshotWhitelist(cb func() bool) ([]store.Whitelist, bool, *Error) {
	var rows []store.Whitelist
	ran, e := s.pinned("whitelist", cb, func(tx store.Queryer) error {
		var err error
		rows, err = store.ListWhitelist(tx)
		return err
	})
	if e != nil {
		return nil, ran, e
	}
	return rows, ran, nil
}
