package config

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func TestTD132NodeAPIKeyWhitespace(t *testing.T) {
	const key = "test-only-td132-node-api-key"
	if looksLikePlaceholder(key) {
		t.Fatal("test key must not be a placeholder")
	}
	for _, ws := range []struct{ name, value string }{
		{"SP", " "}, {"HTAB", "\t"}, {"CR", "\r"}, {"LF", "\n"}, {"VT", "\v"}, {"FF", "\f"},
	} {
		for _, side := range []string{"leading", "trailing"} {
			t.Run("G5_ASCII_"+ws.name+"_"+side, func(t *testing.T) {
				value := ws.value + key
				if side == "trailing" {
					value = key + ws.value
				}
				cfg := Config{Server: ServerConfig{Interface: "test0"}, Auth: AuthConfig{NodeAPIKey: value}}
				err := cfg.Validate()
				const want = "auth.node_api_key has leading or trailing whitespace; HTTP clients cannot send it"
				if err == nil || err.Error() != want {
					t.Fatalf("want whitespace rejection %q, got %v", want, err)
				}
				if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), key) {
					t.Error("whitespace diagnostic contains key material")
				}
			})
		}
	}
	for _, tc := range []struct{ name, value string }{
		{"G5_plain_accepted", key},
		{"G5_NBSP_accepted", "\u00a0" + key + "\u00a0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Server: ServerConfig{Interface: "test0"}, Auth: AuthConfig{NodeAPIKey: tc.value}}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if cfg.Auth.NodeAPIKey != tc.value {
				t.Error("validation changed the key bytes")
			}
		})
	}
	t.Run("G5_pure_whitespace_existing_error", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{Interface: "test0"}, Auth: AuthConfig{NodeAPIKey: " \t\r\n\v\f"}}
		err := cfg.Validate()
		if err == nil || err.Error() != "auth.node_api_key is empty; generate a real key before starting" {
			t.Fatalf("want existing empty-key diagnostic, got %v", err)
		}
	})
	t.Run("G5_NBSP_header_bytes_preserved", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{Interface: "test0"}, Auth: AuthConfig{NodeAPIKey: "\u00a0" + key + "\u00a0"}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		raw := "GET / HTTP/1.1\r\nHost: localhost\r\nX-API-Key: " + cfg.Auth.NodeAPIKey + "\r\n\r\n"
		request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		defer request.Body.Close()
		if got := request.Header.Get("X-API-Key"); got != cfg.Auth.NodeAPIKey {
			t.Error("HTTP parser changed NBSP-surrounded key bytes")
		}
	})
}
