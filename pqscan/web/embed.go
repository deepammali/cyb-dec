// Package webui embeds the static assets for the pqscan web interface so the
// server ships as a single self-contained binary.
package webui

import "embed"

//go:embed index.html style.css app.js
var Files embed.FS
