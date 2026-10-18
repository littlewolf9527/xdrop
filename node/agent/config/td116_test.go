package config

import (
	"strings"
	"testing"
)

func TestTD116NodeAPIKeyRequired(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		valid     bool
	}{
		{name: "empty"},
		{name: "whitespace", key: " \t\r\n"},
		{name: "valid", key: "test-node-key-0001", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Server: ServerConfig{Interface: "test0"}, Auth: AuthConfig{NodeAPIKey: tc.key}}
			err := cfg.Validate()
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "auth.node_api_key") || !strings.Contains(err.Error(), "generate a real key") {
				t.Fatalf("empty key must be rejected with key-generation guidance: %v", err)
			}
		})
	}
}
