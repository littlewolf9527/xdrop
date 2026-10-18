package orch

import (
	"reflect"
	"testing"
	"time"
)

func TestC5AOrch(t *testing.T) {
	t.Run("C5A-interval", func(t *testing.T) {
		now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
		saved := reconcileNow
		reconcileNow = func() time.Time { return now }
		defer func() { reconcileNow = saved }()
		m := New(nil, Options{})
		before := m.opts
		far, near := now.Add(time.Hour), now.Add(30*time.Second)
		m.nodes = []*node{{nextReconcile: [2]time.Time{far, near}, wake: make(chan struct{}, 1)}}
		if !far.After(now.Add(time.Minute)) {
			t.Fatal("invalid distant schedule witness")
		}
		m.SetReconcileInterval(time.Minute)
		before.ReconcileInterval = time.Minute
		if !reflect.DeepEqual(m.opts, before) || !m.nodes[0].nextReconcile[0].Equal(now.Add(time.Minute)) || !m.nodes[0].nextReconcile[1].Equal(near) || len(m.nodes[0].wake) != 0 {
			t.Fatal("interval did not clamp existing schedule exclusively")
		}
		m.SetReconcileInterval(2 * time.Minute)
		if !m.nodes[0].nextReconcile[0].Equal(now.Add(time.Minute)) {
			t.Fatal("lengthening postponed scheduled work")
		}
	})
}
