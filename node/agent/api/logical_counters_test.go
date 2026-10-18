package api

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

type logicalCounterLookup struct {
	t    *testing.T
	wire []byte
	err  error
}

func (m logicalCounterLookup) Lookup(key, out any) error {
	m.t.Helper()
	if key != uint32(0x12345678) {
		m.t.Fatalf("logical ID key=%v", key)
	}
	if m.err != nil {
		return m.err
	}
	values := make([]LogicalRuleCounters, len(m.wire)/40)
	if err := binary.Read(bytes.NewReader(m.wire), binary.LittleEndian, &values); err != nil {
		m.t.Fatal(err)
	}
	*out.(*[]LogicalRuleCounters) = values
	return nil
}
func TestReadLogicalRuleCounters(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		got, err := ReadLogicalRuleCounters(logicalCounterLookup{t: t, err: fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)}, 0x12345678)
		if err != nil || got != (LogicalRuleCounters{}) {
			t.Fatalf("missing got=%+v err=%v", got, err)
		}
	})
	t.Run("all-CPUs-and-wire-offsets", func(t *testing.T) {
		// Golden bytes are assembled by offsets, independently of the Go struct.
		wire := make([]byte, 3*40)
		for i, pair := range [][2]uint64{{2, 1}, {0x100000003, 0x100000002}, {19, 7}} {
			binary.LittleEndian.PutUint64(wire[i*40:], pair[0])
			binary.LittleEndian.PutUint64(wire[i*40+8:], pair[1])
		}
		got, err := ReadLogicalRuleCounters(logicalCounterLookup{t: t, wire: wire}, 0x12345678)
		want := LogicalRuleCounters{Match: 0x100000018, Drop: 0x10000000a}
		if err != nil || got != want {
			t.Fatalf("all CPU sum got=%+v want=%+v err=%v", got, want, err)
		}
	})
	t.Run("lookup-error", func(t *testing.T) {
		failure := errors.New("map unavailable")
		got, err := ReadLogicalRuleCounters(logicalCounterLookup{t: t, err: failure}, 0x12345678)
		if !errors.Is(err, failure) || got != (LogicalRuleCounters{}) {
			t.Fatalf("error got=%+v err=%v", got, err)
		}
	})
}
