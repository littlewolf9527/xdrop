package service

import "time"

// Clock is a small time abstraction used by stats cache so tests can drive
// refresh ticks deterministically without wall-clock sleeps.
//
// Production wires RealClock; tests inject FakeClock (defined in the test
// files) to advance virtual time and emit ticker events on demand. We
// deliberately do NOT pull in a third-party clock library — the contract
// here is small enough to maintain in-tree.
type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker mirrors time.Ticker via a small interface that fake tickers can
// satisfy without exposing the real Ticker type.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// RealClock is the production Clock; thin wrapper around the time package.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) NewTicker(d time.Duration) Ticker {
	return &realTicker{t: time.NewTicker(d)}
}

type realTicker struct {
	t *time.Ticker
}

func (r *realTicker) C() <-chan time.Time { return r.t.C }
func (r *realTicker) Stop()               { r.t.Stop() }
