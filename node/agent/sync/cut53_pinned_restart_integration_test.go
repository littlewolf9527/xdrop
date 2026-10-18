//go:build linux && integration

package sync

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"golang.org/x/sys/unix"
)

func cut53RestartKeys(t *testing.T, m *ebpf.Map) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var cursor any
	for {
		key := make([]byte, m.KeySize())
		err := m.NextKey(cursor, key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[string(key)] = true
		cursor = key
	}
}

// Use private real pins, reopen the same kernel map IDs, clear before handler
// construction, then pull the post-deletion rule set through SyncOnStartup.
func TestCut53PinnedRestartNoConditionOrphans(t *testing.T) {
	parent := os.Getenv("XDROP_CUT53_BPFFS_DIR")
	if parent == "" {
		t.Fatal("XDROP_CUT53_BPFFS_DIR must name a private lab bpffs directory")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(parent, &fs); err != nil || uint64(fs.Type) != 0xcafe4a11 {
		t.Fatalf("private restart pin directory is not bpffs: type=%x err=%v", fs.Type, err)
	}
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			dir, err := os.MkdirTemp(parent, "cut53-restart-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(dir); err != nil {
					t.Error(err)
				}
			})
			f := cut5ReplayOpen(t)
			text := "64"
			rules := make([]api.Rule, 3)
			for i := range rules {
				rules[i] = api.Rule{ID: fmt.Sprintf("restart-%d", i), LogicalID: uint32(17 + i), SrcIP: fmt.Sprintf("192.0.2.%d", i+1), Protocol: "tcp", Action: "drop", TTL: &text}
				if isCIDR {
					rules[i].SrcIP, rules[i].SrcCIDR = "", fmt.Sprintf("192.0.2.%d/28", i*16)
				}
			}
			active := func(c *ebpf.Collection) string {
				var slot, rule uint64
				if err := c.Maps["active_config"].Lookup(uint32(0), &slot); err != nil {
					t.Fatal(err)
				}
				if err := c.Maps[[]string{"config_a", "config_b"}[slot]].Lookup(uint32(api.ConfigRuleMapSelector), &rule); err != nil {
					t.Fatal(err)
				}
				names := []string{"cond_a", "cond_b"}
				if isCIDR {
					names = []string{"cidr_cond_a", "cidr_cond_b"}
				}
				return names[rule]
			}
			if result, err := f.h.DoAtomicSync(rules); err != nil || result.Added != 3 {
				t.Fatalf("restart seed result=%+v err=%v", result, err)
			}
			oldName := active(f.coll)
			oldKeys := cut53RestartKeys(t, f.coll.Maps[oldName])
			oldRows := map[string][]byte{}
			for key := range oldKeys {
				value := make([]byte, f.coll.Maps[oldName].ValueSize())
				if err := f.coll.Maps[oldName].Lookup([]byte(key), value); err != nil {
					t.Fatal(err)
				}
				oldRows[key] = value
			}
			if len(oldKeys) != 3 {
				t.Fatalf("restart seed distinct groups=%d want=3", len(oldKeys))
			}
			if result, err := f.h.DoAtomicSync(rules[:2]); err != nil || result.Added != 2 {
				t.Fatalf("restart delete full result=%+v err=%v", result, err)
			}
			for key := range cut53RestartKeys(t, f.coll.Maps[active(f.coll)]) {
				delete(oldKeys, key)
			}
			if len(oldKeys) != 1 {
				t.Fatalf("removed condition key count=%d want=1", len(oldKeys))
			}
			conditionNames := []string{"cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b"}
			// Successful full sync removes the deleted tuple from both copies. Reinsert only the
			// captured deleted row as a dirty-pin fixture, representing a
			// previous interrupted cleanup; the active generation stays deleted.
			if oldName == active(f.coll) {
				t.Fatal("deletion did not switch rule generation")
			}
			for key := range oldKeys {
				if err := f.coll.Maps[oldName].Put([]byte(key), oldRows[key]); err != nil {
					t.Fatal(err)
				}
			}
			stale := 0
			for _, name := range conditionNames {
				for key := range cut53RestartKeys(t, f.coll.Maps[name]) {
					if oldKeys[key] {
						stale++
					}
				}
			}
			if stale == 0 {
				t.Fatal("restart witness did not retain the deleted tuple in the old generation")
			}
			// ELF data-section names (for example .rodata) are not bpffs
			// basenames: Linux 6.12 bpf_lookup rejects a dot with -EPERM.
			// Encode every name bijectively; keep the collection keys and all
			// maps, including frozen data sections, unchanged on reopening.
			pinPath := func(name string) string {
				return filepath.Join(dir, "map-"+hex.EncodeToString([]byte(name)))
			}
			ids := map[string]ebpf.MapID{}
			dottedNames := 0
			for name, m := range f.coll.Maps {
				if m.IsPinned() {
					t.Fatalf("fixture map %q was already pinned", name)
				}
				info, err := m.Info()
				if err != nil {
					t.Fatal(err)
				}
				id, ok := info.ID()
				if !ok {
					t.Fatal("kernel map ID unavailable")
				}
				ids[name] = id
				if strings.Contains(name, ".") {
					dottedNames++
					// Reach the original failing syscall with the same map FD.
					// The succeeding encoded pin below isolates the basename
					// from map flags, freeze state and bpffs permissions.
					if err := m.Pin(filepath.Join(dir, name)); !errors.Is(err, unix.EPERM) {
						t.Fatalf("dotted pin %q: got %v want EPERM", name, err)
					}
					if m.IsPinned() {
						t.Fatalf("failed dotted pin %q changed pin state", name)
					}
				}
				if err := m.Pin(pinPath(name)); err != nil {
					t.Fatalf("pin map %q as %q (id=%d flags=%#x): %v", name, filepath.Base(pinPath(name)), id, info.Flags, err)
				}
				if strings.Contains(name, ".") {
					t.Logf("CUT53_PIN_PATH map=%q original=EPERM encoded=PASS same_fd=1 id=%d", name, id)
				}
			}
			if dottedNames == 0 {
				t.Fatal("pin-path witness did not reach an ELF data-section name containing a dot")
			}
			if f.wl.IsPinned() {
				t.Fatal("fixture whitelist_b was already pinned")
			}
			wlInfo, err := f.wl.Info()
			if err != nil {
				t.Fatal(err)
			}
			wlID, ok := wlInfo.ID()
			if !ok || wlInfo.Flags != 0 {
				t.Fatalf("fixture whitelist_b: ID available=%v flags=%#x want=0", ok, wlInfo.Flags)
			}
			if err := f.wl.Pin(filepath.Join(dir, "whitelist_b")); err != nil {
				t.Fatalf("pin whitelist_b (id=%d flags=%#x): %v", wlID, wlInfo.Flags, err)
			}
			f.h.Shutdown()
			f.coll.Close()
			f.wl.Close()
			spec, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BPF_ELF"))
			if err != nil {
				t.Fatal(err)
			}
			replacements := map[string]*ebpf.Map{}
			for name, ms := range spec.Maps {
				if (ms.Type == ebpf.Hash || ms.Type == ebpf.PerCPUHash || ms.Type == ebpf.LPMTrie) && ms.MaxEntries > 256 {
					ms.MaxEntries = 256
				}
				m, err := ebpf.LoadPinnedMap(pinPath(name), nil)
				if err != nil {
					t.Fatalf("reopen map %q as %q: %v", name, filepath.Base(pinPath(name)), err)
				}
				t.Cleanup(func() { m.Close() })
				replacements[name] = m
				info, err := m.Info()
				if err != nil {
					t.Fatal(err)
				}
				id, ok := info.ID()
				if !ok || id != ids[name] {
					t.Fatalf("restart replaced kernel map %s: %d want=%d", name, id, ids[name])
				}
			}
			if len(replacements) != len(ids) {
				t.Fatalf("restart map coverage: reopened=%d pinned=%d", len(replacements), len(ids))
			}
			c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			wl, err := ebpf.LoadPinnedMap(filepath.Join(dir, "whitelist_b"), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { wl.Close() })
			reopenedWL, err := wl.Info()
			if err != nil {
				t.Fatal(err)
			}
			if id, ok := reopenedWL.ID(); !ok || id != wlID {
				t.Fatalf("restart replaced kernel whitelist_b: %d want=%d", id, wlID)
			}
			if err := api.PreparePinnedStartup(c, &ebpf.Collection{Maps: map[string]*ebpf.Map{"whitelist_b": wl}}); err != nil {
				t.Fatal(err)
			}
			for _, name := range conditionNames {
				if keys := cut53RestartKeys(t, c.Maps[name]); len(keys) != 0 {
					t.Fatalf("startup retained condition map %s rows=%d", name, len(keys))
				}
			}
			m := c.Maps
			mgr := cidr.NewManager(m["sv4_cidr_trie"], m["dv4_cidr_trie"], m["sv6_cidr_trie"], m["dv6_cidr_trie"], m["sv4_cidr_trie_b"], m["dv4_cidr_trie_b"], m["sv6_cidr_trie_b"], m["dv6_cidr_trie_b"])
			h := api.NewHandlers(m["blacklist"], m["whitelist"], wl, m["stats"], m["config_a"], m["config_b"], m["active_config"], m["cidr_blacklist"], mgr, m["blacklist_b"], m["cidr_blist_b"], nil, m["id_counts"], m["cond_a"], m["cond_b"], m["cidr_cond_a"], m["cidr_cond_b"], m["id_rl_states"], m["cond_row_missing"])
			t.Cleanup(h.Shutdown)
			body, err := json.Marshal(map[string]any{"rules": rules[:2]})
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.POST("/atomic", h.AtomicSync)
			router.POST("/whitelist", h.SyncWhitelistHandler)
			for path, payload := range map[string][]byte{"/atomic": body, "/whitelist": []byte(`{"entries":[]}`)} {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(payload)))
				if w.Code != 200 {
					t.Fatalf("pinned startup push %s: %d %s", path, w.Code, w.Body)
				}
			}
			activeName := active(c)
			shadowName := map[string]string{"cond_a": "cond_b", "cond_b": "cond_a", "cidr_cond_a": "cidr_cond_b", "cidr_cond_b": "cidr_cond_a"}[activeName]
			activeKeys := cut53RestartKeys(t, m[activeName])
			for _, name := range conditionNames {
				keys := cut53RestartKeys(t, m[name])
				want := 0
				if name == activeName || name == shadowName {
					want = 2
				}
				if len(keys) != want {
					t.Fatalf("pinned restart %s rows=%d distinct groups=%d", name, len(keys), want)
				}
				if name == shadowName {
					for key := range keys {
						if !activeKeys[key] {
							t.Fatalf("pinned restart mirror key missing from %s: %x", activeName, key)
						}
						activeValue := make([]byte, m[activeName].ValueSize())
						shadowValue := make([]byte, m[name].ValueSize())
						if err := m[activeName].Lookup([]byte(key), activeValue); err != nil {
							t.Fatal(err)
						}
						if err := m[name].Lookup([]byte(key), shadowValue); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(activeValue, shadowValue) {
							t.Fatalf("pinned restart mirror bytes differ in %s: %x", name, key)
						}
					}
				}
				for key := range oldKeys {
					if keys[key] {
						t.Fatalf("pinned restart orphan condition tuple in %s: %x", name, key)
					}
				}
			}
			t.Logf("CUT53_PINNED_RESTART cidr=%v deleted_groups=1 retained_groups=2 same_kernel_maps=%d condition_maps=4 orphan_rows=0 mirror=1", isCIDR, len(ids))
		})
	}
}
