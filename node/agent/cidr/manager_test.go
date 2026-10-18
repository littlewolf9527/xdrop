package cidr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

var _ TrieWriter = (*ebpf.Map)(nil)

type fakeTrie struct {
	entries                               map[string]uint32
	putErr, deleteErr, nextErr, lookupErr error
	putCalls, deleteCalls                 int
	size, capacity                        uint32
	events                                []string
}

func newFakeTrie(size uint32) *fakeTrie {
	return &fakeTrie{entries: map[string]uint32{}, size: size, capacity: 50000}
}
func fakeKey(key interface{}) string {
	if b, ok := key.([]byte); ok {
		return string(b)
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, key); err != nil {
		panic(err)
	}
	return b.String()
}
func (f *fakeTrie) KeySize() uint32    { return f.size }
func (f *fakeTrie) MaxEntries() uint32 { return f.capacity }
func (f *fakeTrie) Put(key, value interface{}) error {
	f.putCalls++
	f.events = append(f.events, "put")
	if f.putErr != nil {
		return f.putErr
	}
	k := fakeKey(key)
	if _, exists := f.entries[k]; !exists && len(f.entries) >= int(f.capacity) {
		return errors.New("full")
	}
	f.entries[k] = value.(uint32)
	return nil
}
func (f *fakeTrie) Delete(key interface{}) error {
	f.deleteCalls++
	f.events = append(f.events, "delete")
	if f.deleteErr != nil {
		return f.deleteErr
	}
	k := fakeKey(key)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}
func (f *fakeTrie) Lookup(key, out interface{}) error {
	if f.lookupErr != nil {
		return f.lookupErr
	}
	id, ok := f.entries[fakeKey(key)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*uint32) = id
	return nil
}
func (f *fakeTrie) NextKey(cursor, out interface{}) error {
	if f.nextErr != nil {
		return f.nextErr
	}
	keys := make([]string, 0, len(f.entries))
	for key := range f.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if cursor == nil || key > fakeKey(cursor) {
			*out.(*[]byte) = []byte(key)
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}

const testCIDR = "10.0.0.0/24"
const testCIDR2 = "192.168.0.0/24"

func newTestManager() (*Manager, [2][4]*fakeTrie) {
	var ts [2][4]*fakeTrie
	for slot := range ts {
		for i := range ts[slot] {
			size := uint32(8)
			if i >= 2 {
				size = 20
			}
			ts[slot][i] = newFakeTrie(size)
		}
	}
	return NewManager(ts[0][0], ts[0][1], ts[0][2], ts[0][3], ts[1][0], ts[1][1], ts[1][2], ts[1][3]), ts
}
func TestReserveSrcID_AssignsUniqueIDs(t *testing.T) {
	m, _ := newTestManager()
	a, e := m.ReserveSrcID(testCIDR)
	if e != nil {
		t.Fatal(e)
	}
	b, e := m.ReserveSrcID(testCIDR2)
	if e != nil || b <= a {
		t.Fatal(a, b, e)
	}
	again, e := m.ReserveSrcID(testCIDR)
	if e != nil || again != a {
		t.Fatal(a, again, e)
	}
}
func TestReleaseSrcID_UnknownCIDRReturnsError(t *testing.T) {
	m, _ := newTestManager()
	if err := m.ReleaseSrcID(testCIDR); err == nil {
		t.Fatal("unknown release silently accepted")
	}
}

// Migrates both refcount tests and the old debt/undo tests to I1/I2/I4/I6.
func TestDingManagerStatesAndBorrowSettlement(t *testing.T) {
	for i := 0; i < 4; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			m, ts := newTestManager()
			prefix := testCIDR
			if i >= 2 {
				prefix = "fd00::/64"
			}
			reserve, undo, release, get := m.ReserveSrcID, m.UndoSrcReservation, m.ReleaseSrcID, m.GetSrcID
			if i%2 == 1 {
				reserve, undo, release, get = m.ReserveDstID, m.UndoDstReservation, m.ReleaseDstID, m.GetDstID
			}
			id, e := reserve(prefix)
			if e != nil {
				t.Fatal(e)
			}
			same, e := reserve(prefix)
			if e != nil || same != id {
				t.Fatal("shared identity", same, id, e)
			}
			if ts[0][i].putCalls+ts[1][i].putCalls != 0 {
				t.Fatal("reservation wrote trie")
			}
			if e = undo(prefix); e != nil {
				t.Fatal(e)
			}
			if e = undo(prefix); e != nil {
				t.Fatal(e)
			}
			if _, ok := get(prefix); ok || ts[0][i].deleteCalls+ts[1][i].deleteCalls != 0 {
				t.Fatal("undo must be memory only")
			}
			next, e := reserve(prefix)
			if e != nil || next <= id {
				t.Fatal("cancelled ID reused")
			}
			if e = m.Align(1, m.Snapshot([2][]string{})); e != nil {
				t.Fatal(e)
			}
			if ts[0][i].putCalls != 0 || ts[1][i].putCalls != 1 {
				t.Fatal("shadow-only publication")
			}
			for n := 0; n < 3; n++ {
				if _, e = reserve(prefix); e != nil {
					t.Fatal(e)
				}
			}
			if e = m.Align(1, m.Snapshot([2][]string{})); e != nil || ts[1][i].putCalls != 1 {
				t.Fatal("shared prefix duplicate write", e)
			}
			for n := 0; n < 3; n++ {
				if e = undo(prefix); e != nil {
					t.Fatal(e)
				}
			}
			if got, ok := get(prefix); !ok || got != next {
				t.Fatal("borrow rollback lost live identity")
			}
			ts[1][i].deleteErr = errors.New("delete fault")
			if e = release(prefix); e != nil {
				t.Fatal("release performed trie I/O", e)
			}
			if _, ok := get(prefix); ok || len(ts[1][i].entries) != 1 || ts[1][i].deleteCalls != 0 {
				t.Fatal("old copy changed before receipt")
			}
			if e = m.Align(1, m.Snapshot([2][]string{})); e == nil || m.known[1] {
				t.Fatal("failed alignment not unknown")
			}
			ts[1][i].deleteErr = nil
			if e = m.CatchUp(1); e != nil || len(ts[1][i].entries) != 0 || !m.known[1] {
				t.Fatal("unknown actual-content recovery", e)
			}
		})
	}
}
func TestPrefixABFailedPutCancellationAndIDOverwrite(t *testing.T) {
	m, ts := newTestManager()
	id, e := m.ReserveDstID(testCIDR)
	if e != nil {
		t.Fatal(e)
	}
	ts[1][1].putErr = errors.New("put fault")
	if e = m.Align(1, m.Snapshot([2][]string{})); e == nil || m.known[1] {
		t.Fatal("put failure missing")
	}
	if e = m.UndoDstReservation(testCIDR); e != nil || ts[1][1].deleteCalls != 0 {
		t.Fatal("undo performed I/O", e)
	}
	ts[1][1].putErr = nil
	next, e := m.ReserveDstID(testCIDR)
	if e != nil || next <= id {
		t.Fatal("ID reused")
	}
	key, _ := trieKey(testCIDR, false)
	ts[1][1].entries[string(key)] = id
	if e = m.CatchUp(1); e != nil {
		t.Fatal(e)
	}
	if ts[1][1].entries[string(key)] != next || ts[1][1].putCalls != 2 {
		t.Fatal("stale ID not overwritten")
	}
}
func TestPrefixABUnknownFullDeletesFirst(t *testing.T) {
	m, ts := newTestManager()
	trie := ts[1][0]
	trie.capacity = 2
	for _, p := range []string{"10.1.0.0/24", "10.2.0.0/24"} {
		key, _ := trieKey(p, false)
		trie.entries[string(key)] = 99
	}
	for _, p := range []string{"10.3.0.0/24", "10.4.0.0/24"} {
		if _, e := m.ReserveSrcID(p); e != nil {
			t.Fatal(e)
		}
	}
	if len(trie.entries) != 2 || trie.MaxEntries() != 2 {
		t.Fatal("full-copy guard")
	}
	if e := m.CatchUp(1); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(trie.events, []string{"delete", "delete", "put", "put"}) || len(trie.entries) != 2 {
		t.Fatal(trie.events)
	}
	if !reflect.DeepEqual(trie.entries, m.Snapshot([2][]string{})[0]) {
		t.Fatal("extra/missing prefix")
	}
}
func TestPrefixABReadFailureIsUnknown(t *testing.T) {
	for _, kind := range []string{"next", "lookup"} {
		t.Run(kind, func(t *testing.T) {
			m, ts := newTestManager()
			trie := ts[1][0]
			key, _ := trieKey(testCIDR, false)
			trie.entries[string(key)] = 8
			injected := errors.New(kind)
			if kind == "next" {
				trie.nextErr = injected
			} else {
				trie.lookupErr = injected
			}
			if e := m.Align(1, TrieEntries{}); !errors.Is(e, injected) || m.known[1] || trie.deleteCalls != 0 || trie.putCalls != 0 {
				t.Fatal("read failure changed trie or lost error", e)
			}
			trie.nextErr = nil
			trie.lookupErr = nil
			if e := m.CatchUp(1); e != nil || len(trie.entries) != 0 {
				t.Fatal("read failure recovery", e)
			}
		})
	}
}
