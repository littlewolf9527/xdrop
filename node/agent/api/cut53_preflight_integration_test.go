//go:build linux && integration

package api

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func cut53BusinessSnapshot(t *testing.T, h *Handlers) []map[string]string {
	t.Helper()
	var result []map[string]string
	for _, m := range []*ebpf.Map{h.blacklist, h.blacklistB, h.cidrBlacklist, h.cidrBlacklistB, h.condA, h.condB, h.cidrCondA, h.cidrCondB, h.configA, h.configB, h.activeConfig} {
		result = append(result, b7Snapshot(t, m))
	}
	return result
}

func TestCut53EmptyIDsConditionGroupKernelZeroWrite(t *testing.T) {
	h := newBLCIDRTestHandlers(t)
	if _, err := h.DoAtomicSync([]Rule{{ID: "sentinel", SrcIP: "198.51.100.9", Action: "drop", LogicalID: 9}}); err != nil {
		t.Fatal(err)
	}
	m, trie := cut53PendingManager(t)
	h.cidrMgr = m
	before := cut53BusinessSnapshot(t, h)
	managerBefore, trieBefore := fmt.Sprintf("%#v", m), *trie
	cut53EmptyGroupCall(t, h)
	if !reflect.DeepEqual(before, cut53BusinessSnapshot(t, h)) || managerBefore != fmt.Sprintf("%#v", m) || trieBefore != *trie {
		t.Fatal("I6 original empty-ID input changed map bytes, Manager or withdrawal debt")
	}
	t.Log("CUT53_EMPTY_IDS_KERNEL maps=11 unchanged=11 conflicts=2 withdrawal_calls=0")
}
