package cidr

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 甲-2 / MA-2: exercise trieKey itself against the sealed byte fixture.
func TestFlipATrieKeyGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "lpm_keys_goebpf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		CIDR   string `json:"cidr"`
		Family int    `json:"family"`
		KeyLen int    `json:"key_len"`
		HexKey string `json:"hex_key"`
	}
	if err = json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 8 {
		t.Fatal("golden fixture count")
	}
	for _, item := range items {
		t.Run(item.CIDR, func(t *testing.T) {
			want, err := hex.DecodeString(item.HexKey)
			if err != nil || len(want) != item.KeyLen {
				t.Fatal("golden encoding", err)
			}
			got, err := trieKey(item.CIDR, item.Family == 6)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("trieKey golden mismatch: got=%x want=%x error=%v", got, want, err)
			}
		})
	}
}
