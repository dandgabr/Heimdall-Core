package webui

import "embed"

// distFS is the compiled Svelte SPA, embedded into the binary so the daemon is
// a single artifact with no runtime asset dependency (ADR-002 §2: no Wails, no
// Tauri, no external files).
//
// The directive REQUIRES dist/ to exist at compile time; go:embed fails the
// build if it is absent. That is deliberate: a Go build must never silently
// produce a binary that cannot serve the GUI. `make web` (or `pnpm build` in
// web/) regenerates dist/ from source; the tree is committed so a plain
// `go build` works on a machine with no Node installed.
//
//go:embed dist
var distFS embed.FS

// base is the directory inside distFS that holds the Vite output.
const base = "dist"
