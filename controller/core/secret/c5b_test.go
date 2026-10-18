package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func master(t *testing.T) (*Key, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master")
	if err := Init(path); err != nil {
		t.Fatal("master fixture")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("master permissions")
	}
	k, err := Load(path)
	if err != nil {
		t.Fatal("load master fixture")
	}
	return k, path
}
func TestC5BSecret(t *testing.T) {
	t.Run("C5B-nonce", func(t *testing.T) {
		k, _ := master(t)
		a, b, e := k.Seal("a", "TEST_ONLY_NODE_KEY")
		c, d, f := k.Seal("a", "TEST_ONLY_NODE_KEY")
		if e != nil || f != nil || len(a) != 12 || len(c) != 12 || bytes.Equal(a, c) || bytes.Equal(b, d) {
			t.Fatal("fresh nonce and ciphertext required")
		}
	})
	t.Run("C5B-aad", func(t *testing.T) {
		k, _ := master(t)
		a, b, e := k.Seal("a", "TEST_ONLY_NODE_KEY")
		c, d, f := k.Seal("b", "TEST_ONLY_NODE_KEY")
		for _, row := range []struct {
			name          string
			nonce, sealed []byte
		}{{"a", a, b}, {"b", c, d}} {
			plain, err := k.Open(row.name, row.nonce, row.sealed)
			if e != nil || f != nil || err != nil || plain != "TEST_ONLY_NODE_KEY" {
				t.Fatal("own row prerequisite")
			}
		}
		if _, err := k.Open("b", a, b); err == nil {
			t.Fatal("paired transplant accepted")
		}
		t.Log("own_rows=2 paired_transplant_rejected=1")
	})
	t.Run("C5B-master-file", func(t *testing.T) {
		_, path := master(t)
		before, _ := os.ReadFile(path)
		if Init(path) == nil {
			t.Fatal("overwrote master")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("master changed")
		}
		for _, mode := range []string{"permission", "length", "base64"} {
			t.Run(mode, func(t *testing.T) {
				_, path := master(t)
				if mode == "permission" {
					if os.Chmod(path, 0644) != nil {
						t.Fatal("chmod fixture")
					}
				} else {
					b := make([]byte, 31)
					if _, e := rand.Read(b); e != nil {
						t.Fatal("random fixture")
					}
					text := base64.StdEncoding.EncodeToString(b)
					if mode == "base64" {
						text = "TEST_ONLY_INVALID_BASE64!"
					}
					if os.WriteFile(path, []byte(text), 0600) != nil {
						t.Fatal("bad master fixture")
					}
				}
				content, _ := os.ReadFile(path)
				_, err := Load(path)
				if err == nil || !strings.Contains(err.Error(), "secret_key_file") || strings.Contains(err.Error(), string(content)) {
					t.Fatal("master rejection or redaction")
				}
			})
		}
	})
}
