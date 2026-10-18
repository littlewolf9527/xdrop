package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCtlCut1DryrunCLI(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		var out bytes.Buffer
		if rc := run([]string{"-h"}, &out); rc != 0 || !strings.Contains(out.String(), "stop the controller") || !strings.Contains(out.String(), "not a consistent snapshot") {
			t.Fatalf("help rc=%d: %s", rc, &out)
		}
	})
	t.Run("arguments", func(t *testing.T) {
		for _, args := range [][]string{nil, {"-unknown"}, {"-db", "ignored", "extra"}} {
			var out bytes.Buffer
			if rc := run(args, &out); rc != 2 {
				t.Fatalf("%v: rc=%d", args, rc)
			}
		}
	})
	t.Run("empty-source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.db")
		if e := os.WriteFile(path, nil, 0600); e != nil {
			t.Fatal(e)
		}
		var out bytes.Buffer
		if rc := run([]string{"-db", path}, &out); rc != 0 {
			t.Fatalf("rc=%d: %s", rc, &out)
		}
		info, e := os.Stat(path)
		if e != nil || info.Size() != 0 {
			t.Fatal("source was modified", e)
		}
	})
}
