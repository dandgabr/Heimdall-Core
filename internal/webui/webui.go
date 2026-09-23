// Package webui serves the embedded management GUI (a Svelte SPA) from the same
// mux as the Management API.
//
// # Trust model (ADR-SEC-06)
//
// The SPA is mounted under /web/ on the application mux, so it inherits the
// catch-all LocalOnly and HostGuard guards BY CONSTRUCTION — the same property
// every other route relies on. The asset surface is READ-class: it is served to
// a loopback caller without a token, because the browser must load the login
// screen before it can present one. It carries no secret: the assets are static
// build output.
//
// The SPA itself authenticates every Management API call with the management
// token in the Authorization header (never a cookie, never a query parameter),
// so a replayed/shared asset URL grants nothing.
package webui

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// Prefix is the SPA mount point. It matches the Vite `base` and the
// middleware.isManagementOrGUI origin-check class, so a future mutating GUI
// endpoint is anti-CSRF checked without an edit there.
const Prefix = "/web/"

// indexName is the SPA shell the hash router boots from.
const indexName = "index.html"

// assetCacheControl is the immutable cache policy for a content-hashed asset:
// Vite emits `assets/<name>-<hash>.ext`, so the URL changes whenever the bytes
// do and a year-long immutable cache is safe. index.html is the opposite
// (no-store), so a redeploy is picked up immediately.
const assetCacheControl = "public, max-age=31536000, immutable"

// csp is a strict, self-only policy that holds because the SPA ships NO inline
// script or style: every script and stylesheet is a same-origin external asset.
// `connect-src 'self'` is what lets the SPA call /api/mgmt/* on the same origin.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; base-uri 'none'; " +
	"form-action 'none'; frame-ancestors 'none'"

// Handler serves the embedded SPA asset tree with a client-route fallback.
//
// read is a seam: production reads the embedded build, a test injects a source
// so the "index missing" defensive branch is reachable (the embed makes it
// impossible in a real build).
type Handler struct {
	read func(name string) ([]byte, error)
}

// New builds the handler over the embedded build.
func New() *Handler {
	return &Handler{read: func(name string) ([]byte, error) {
		return fs.ReadFile(distFS, base+"/"+name)
	}}
}

// Register mounts the SPA on mux.
//
// Only GET/HEAD are routed to the asset handler; any other method falls through
// to the mux's own 405, which the shared ErrorEnvelope renders in the i18n JSON
// format (no new error shape). The bare "/" redirects to Prefix so the absolute
// /web/ asset URLs in index.html resolve from any entry point.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET "+Prefix, h)
	mux.HandleFunc("GET /web", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Prefix, http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Prefix, http.StatusFound)
	})
}

// ServeHTTP serves a file if it exists, else the SPA shell (client-route
// fallback). The path is cleaned before it reaches the asset source, so a
// traversal attempt like /web/../../etc/passwd resolves inside the tree (and
// misses), never outside it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	rel := strings.TrimPrefix(r.URL.Path, Prefix)
	if rel == "" {
		h.serveIndex(w)
		return
	}
	name := path.Clean("/" + rel)[1:] // anchored clean: never escapes the tree
	body, err := h.read(name)
	if err != nil {
		h.serveIndex(w)
		return
	}
	writeAsset(w, name, body)
}

// serveIndex writes the SPA shell with a no-store cache policy.
func (h *Handler) serveIndex(w http.ResponseWriter) {
	body, err := h.read(indexName)
	if err != nil {
		// Defensive: the embed guarantees index.html exists, so a healthy build
		// never reaches this. A broken/dist-missing build fails at compile time
		// instead, but writing a clear 500 beats an empty body.
		http.Error(w, "embedded index.html is missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// writeAsset writes a hashed build asset with its content type and immutable
// cache policy.
func writeAsset(w http.ResponseWriter, name string, body []byte) {
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", assetCacheControl)
	_, _ = w.Write(body)
}

// setSecurityHeaders applies the response hardening that does not depend on the
// route. It is set on every asset response.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}
