package cidr

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// NEW-UT-03 (§8.1.2): compile-time assertion that `*ebpf.Map` satisfies
// cidr.TrieWriter without an explicit adapter. If cilium/ebpf ever tightens
// Put / Delete signatures, this breaks the test build (not the main binary),
// giving early warning.
var _ TrieWriter = (*ebpf.Map)(nil)

// fakeTrie is a minimal cidr.TrieWriter implementation used by Manager's
// writeTrie / deleteTrie call sites. Only Put and Delete are needed — a
// two-method narrow interface (§5.3 / §5.7 of the migration proposal)
// replaces the 19-method goebpf.Map mock we used to need.
type fakeTrie struct {
	entries map[string]struct{} // key-bytes hex → presence

	// Injected failures
	putErr    error
	deleteErr error

	// Call counters for assertions
	putCalls    int
	deleteCalls int
}

func newFakeTrie() *fakeTrie {
	return &fakeTrie{entries: make(map[string]struct{})}
}

func (f *fakeTrie) Put(key, _ interface{}) error {
	f.putCalls++
	if f.putErr != nil {
		return f.putErr
	}
	f.entries[fmt.Sprintf("%v", key)] = struct{}{}
	return nil
}

func (f *fakeTrie) Delete(key interface{}) error {
	f.deleteCalls++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.entries, fmt.Sprintf("%v", key))
	return nil
}

func (f *fakeTrie) len() int { return len(f.entries) }

// --- Tests ---

const testCIDR = "10.0.0.0/24"
const testCIDR2 = "192.168.0.0/24"

func newTestManager() (*Manager, *fakeTrie, *fakeTrie, *fakeTrie, *fakeTrie) {
	srcV4, dstV4 := newFakeTrie(), newFakeTrie()
	srcV6, dstV6 := newFakeTrie(), newFakeTrie()
	return NewManager(srcV4, dstV4, srcV6, dstV6), srcV4, dstV4, srcV6, dstV6
}

// TestAllocSrcID_AssignsUniqueIDs verifies each new CIDR gets a fresh ID and
// the same CIDR returns the same ID with incremented refcount.
func TestAllocSrcID_AssignsUniqueIDs(t *testing.T) {
	m, _, _, _, _ := newTestManager()

	id1, err := m.AllocSrcID(testCIDR)
	if err != nil {
		t.Fatalf("first alloc failed: %v", err)
	}
	id2, err := m.AllocSrcID(testCIDR2)
	if err != nil {
		t.Fatalf("second alloc failed: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected different IDs for different CIDRs, got %d for both", id1)
	}

	// Same CIDR again → same ID, not a new one.
	id1Again, err := m.AllocSrcID(testCIDR)
	if err != nil {
		t.Fatalf("re-alloc failed: %v", err)
	}
	if id1Again != id1 {
		t.Fatalf("re-alloc of same CIDR returned new ID %d (expected %d)", id1Again, id1)
	}
}

// TestReleaseSrcID_RefcountSemantics verifies BUG-020/021: trie delete happens
// only on last reference, and map state mirrors trie state.
func TestReleaseSrcID_RefcountSemantics(t *testing.T) {
	m, srcV4, _, _, _ := newTestManager()

	// Two allocs → refcount = 2, one trie write
	if _, err := m.AllocSrcID(testCIDR); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AllocSrcID(testCIDR); err != nil {
		t.Fatal(err)
	}
	if got := srcV4.putCalls; got != 1 {
		t.Errorf("expected 1 trie put for 2 allocs of same CIDR, got %d", got)
	}

	// First release: refcount 2 → 1, trie untouched
	if err := m.ReleaseSrcID(testCIDR); err != nil {
		t.Fatalf("first release failed: %v", err)
	}
	if got := srcV4.deleteCalls; got != 0 {
		t.Errorf("expected 0 trie deletes after first release, got %d", got)
	}
	if _, ok := m.GetSrcID(testCIDR); !ok {
		t.Error("GetSrcID lost entry after first release (should still be present)")
	}

	// Second release: refcount 1 → 0, trie delete happens
	if err := m.ReleaseSrcID(testCIDR); err != nil {
		t.Fatalf("second release failed: %v", err)
	}
	if got := srcV4.deleteCalls; got != 1 {
		t.Errorf("expected 1 trie delete after last release, got %d", got)
	}
	if _, ok := m.GetSrcID(testCIDR); ok {
		t.Error("GetSrcID still has entry after last release")
	}
}

// TestReleaseSrcID_TrieFailureLeavesStateUnchanged verifies BUG-020: on trie
// delete failure, refcount is NOT decremented, so caller can safely retry.
func TestReleaseSrcID_TrieFailureLeavesStateUnchanged(t *testing.T) {
	m, srcV4, _, _, _ := newTestManager()

	id, err := m.AllocSrcID(testCIDR)
	if err != nil {
		t.Fatal(err)
	}

	// Inject trie delete failure
	srcV4.deleteErr = fmt.Errorf("injected trie delete failure")

	// Release should fail, and state must be preserved
	if err := m.ReleaseSrcID(testCIDR); err == nil {
		t.Fatal("expected release to return error when trie delete fails")
	}

	// Entry must still be present with original ID
	gotID, ok := m.GetSrcID(testCIDR)
	if !ok {
		t.Fatal("entry was removed despite trie delete failure")
	}
	if gotID != id {
		t.Errorf("ID mutated after failed release: got %d, want %d", gotID, id)
	}

	// Clear injection; retry should succeed
	srcV4.deleteErr = nil
	if err := m.ReleaseSrcID(testCIDR); err != nil {
		t.Errorf("retry after cleared failure should succeed, got: %v", err)
	}
	if _, ok := m.GetSrcID(testCIDR); ok {
		t.Error("entry persisted after successful retry")
	}
}

// TestReleaseSrcID_UnknownCIDRReturnsError verifies releasing a CIDR that was
// never alloced is a loud error, not a silent no-op.
func TestReleaseSrcID_UnknownCIDRReturnsError(t *testing.T) {
	m, _, _, _, _ := newTestManager()
	if err := m.ReleaseSrcID(testCIDR); err == nil {
		t.Fatal("expected error when releasing un-alloced CIDR")
	}
}

// TestReleaseDstID_RefcountSemantics mirrors the src test for the dst path.
func TestReleaseDstID_RefcountSemantics(t *testing.T) {
	m, _, dstV4, _, _ := newTestManager()

	if _, err := m.AllocDstID(testCIDR); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AllocDstID(testCIDR); err != nil {
		t.Fatal(err)
	}

	if err := m.ReleaseDstID(testCIDR); err != nil {
		t.Fatal(err)
	}
	if got := dstV4.deleteCalls; got != 0 {
		t.Errorf("expected 0 trie deletes with ref>1, got %d", got)
	}

	if err := m.ReleaseDstID(testCIDR); err != nil {
		t.Fatal(err)
	}
	if got := dstV4.deleteCalls; got != 1 {
		t.Errorf("expected 1 trie delete on last ref, got %d", got)
	}
}

// TestAllocDstID_TrieFailurePreservesIDCounter verifies that when Alloc's
// writeTrie fails, no state is persisted (no phantom entry in cidrs/refs).
func TestAllocDstID_TrieFailurePreservesIDCounter(t *testing.T) {
	m, _, dstV4, _, _ := newTestManager()

	dstV4.putErr = fmt.Errorf("injected put failure")

	if _, err := m.AllocDstID(testCIDR); err == nil {
		t.Fatal("expected error when trie put fails")
	}
	if _, ok := m.GetDstID(testCIDR); ok {
		t.Error("GetDstID has entry despite trie put failure")
	}

	// Retry after clearing injection
	dstV4.putErr = nil
	if _, err := m.AllocDstID(testCIDR); err != nil {
		t.Fatalf("retry after cleared failure should succeed, got: %v", err)
	}
}
