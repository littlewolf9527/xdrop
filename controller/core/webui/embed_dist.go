//go:build !webui

package webui

import "embed"

//go:embed dist
var files embed.FS

const root = "dist"
