//go:build webui

package webui

import (
	"bytes"
	"io/fs"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestC5D1WebUI(t *testing.T) {
	t.Run("index", func(t *testing.T) {
		for _, path := range []string{"/", "/overview"} {
			w := httptest.NewRecorder()
			Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`<script type="module"`)) || bytes.Contains(w.Body.Bytes(), []byte("前端未构建")) || w.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("index %s: code=%d cache=%q body=%s", path, w.Code, w.Header().Get("Cache-Control"), w.Body.String())
			}
		}
	})
	t.Run("all-files", func(t *testing.T) {
		count := 0
		err := filepath.WalkDir("build", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			w := httptest.NewRecorder()
			Handler().ServeHTTP(w, httptest.NewRequest("GET", "/"+filepath.ToSlash(path[len("build/"):]), nil))
			if w.Code != 200 || w.Body.Len() != len(b) {
				t.Errorf("%s: status=%d got=%d want=%d", path, w.Code, w.Body.Len(), len(b))
			}
			count++
			return nil
		})
		if err != nil || count == 0 {
			t.Fatalf("walk files=%d err=%v", count, err)
		}
	})
	t.Run("missing-extension", func(t *testing.T) {
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, httptest.NewRequest("GET", "/absent.js", nil))
		if w.Code != 404 {
			t.Fatalf("got %d", w.Code)
		}
	})
	t.Run("build", func(t *testing.T) {
		cmd := exec.Command("go", "build", "-tags", "webui", "-o", filepath.Join(t.TempDir(), "controller"), "./cmd/xdrop-controller")
		cmd.Dir = "../.."
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	})
}
