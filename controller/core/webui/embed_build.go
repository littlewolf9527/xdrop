//go:build webui

package webui

import "embed"

//go:embed all:build
var files embed.FS

const root = "build"
