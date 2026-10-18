//go:build linux && integration

package bpf

import (
	"golang.org/x/sys/unix"
	"reflect"
	"testing"
)

var nsAccountingStart = func() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_COARSE, &ts); err != nil {
		panic(err)
	}
	return uint64(ts.Nano())
}()

func nsCoarse(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_COARSE, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

func nsLogicalBuffer(name string, cpus int) reflect.Value {
	width := 2
	if name == "id_counts" {
		width = 5
	}
	return reflect.MakeSlice(reflect.SliceOf(reflect.ArrayOf(width, reflect.TypeOf(uint64(0)))), cpus, cpus)
}
