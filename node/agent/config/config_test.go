package config

import "testing"

// OPEN-P2-06 regression: placeholder secrets should be rejected.
// AUD-FIX-002: controller_sync_key is only validated when controller_url is set.
func TestValidate_RejectsPlaceholderKeys(t *testing.T) {
	tests := []struct {
		name    string
		nodeKey string
		syncKey string
		ctrlURL string
		wantErr bool
	}{
		{"real keys + url pass", "abc123def456", "xyz789uvw012", "http://c:8000", false},
		{"real keys without url pass", "abc123def456", "xyz789uvw012", "", false},
		{"CHANGE_ME node_api_key rejected", "CHANGE_ME_NODE_KEY", "real", "", true},
		{"CHANGE_ME sync_key rejected when url set", "real", "CHANGE_ME_SYNC_KEY", "http://c:8000", true},
		{"CHANGE_ME sync_key ALLOWED in pull-only (empty url)", "real", "CHANGE_ME_SYNC_KEY", "", false},
		{"lowercase change-me node rejected", "change-me-node", "real", "", true},
		{"mixed case changeme node rejected", "Changeme123", "real", "", true},
		{"REPLACE_ME node rejected", "REPLACE_ME_KEY", "real", "", true},
		{"empty keys pass (disabled auth)", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{Interface: "eth0"},
				Auth: AuthConfig{
					NodeAPIKey:        tt.nodeKey,
					ControllerSyncKey: tt.syncKey,
					ControllerURL:     tt.ctrlURL,
				},
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestLooksLikePlaceholder(t *testing.T) {
	cases := map[string]bool{
		"":                     false,
		"real-key-abcdef":      false,
		"admin":                false,
		"CHANGE_ME":            true,
		"CHANGE_ME_NODE_KEY":   true,
		"change-me":            true,
		"changeme":             true,
		"Changeme":             true,
		"REPLACE_ME_SECRET":    true,
		"replace_me":           true,
	}
	for input, want := range cases {
		if got := looksLikePlaceholder(input); got != want {
			t.Errorf("looksLikePlaceholder(%q) = %v, want %v", input, got, want)
		}
	}
}
