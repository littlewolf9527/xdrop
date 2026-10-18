package webui

import (
	"bytes"
	"net/http"
	"path"
	"strings"
	"time"
)

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		b, err := files.ReadFile(root + "/" + name)
		if err != nil && path.Ext(name) == "" {
			name = "index.html"
			b, err = files.ReadFile(root + "/" + name)
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
	})
}
