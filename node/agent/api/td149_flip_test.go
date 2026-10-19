package api

import (
	"bytes"
	"testing"
)

// TestTD149FlipPreservesPass: slot 12 (deep chains pass) written at startup must
// survive config flips — rule commit and whitelist publish each copy the active
// config to the shadow before flipping (blind review r1 P2-3). Atomic sync needs
// real logical-state maps: TestTD149AtomicFlipPreservesPass (integration).
func TestTD149FlipPreservesPass(t *testing.T) {
	slot12 := string(cut55Bytes(uint32(ConfigIPv6DeepChainPass)))
	pass := cut55Bytes(uint64(1))
	for _, path := range []string{"commit", "whitelist"} {
		t.Run(path, func(t *testing.T) {
			f := cut55Memory(t)
			for slot := range f.configs {
				f.configs[slot].rows[slot12] = append([]byte(nil), pass...)
			}
			r := cut55Rule("a", 1, "192.0.2.1")
			for step := 0; step < 2; step++ {
				before := f.h.activeSlot
				switch path {
				case "commit":
					rules := []Rule{r}
					if step == 1 {
						rules = nil
					}
					cut55Commit(t, f.h, cut55Group(t, f.h, r, rules...))
				case "whitelist":
					f.h.publishMu.Lock()
					f.h.activeWLSlot = 1 - f.h.activeWLSlot
					err := f.h.publishConfigUpdateForWLSync(0, [64]int{})
					f.h.publishMu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				f.bindConfig()
				got := f.configs[f.h.activeSlot].rows[slot12]
				if f.h.activeSlot == before || !bytes.Equal(got, pass) {
					t.Fatalf("step=%d flipped=%t active slot12=%x want %x", step, f.h.activeSlot != before, got, pass)
				}
			}
			t.Logf("TD149_FLIP path=%s flips=2 active_slot12=1", path)
		})
	}
}
