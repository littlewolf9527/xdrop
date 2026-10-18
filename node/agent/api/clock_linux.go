//go:build linux

package api

import "golang.org/x/sys/unix"

func hitsClock() (uint64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC_COARSE, &ts)
	return uint64(ts.Nano()), err
}
