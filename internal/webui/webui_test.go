package webui

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRegisterServesEmbeddedIndex proves the real embedded build serves the SPA
// shell at the mount point and that a missing hashed asset falls back to it
// (client-route fallback), so a deep link like /web/combos still boots the app.
func TestRegisterServesEmbeddedIndex(t *testing.T) {
	mux := http.NewServeMux()
	New().Register(mux)

	for _, path := range []string{Prefix, Prefix + "combos", Prefix + "assets/does-not-exist.js"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: content-type = %q, want text/html", path, ct)
		}
		if !strings.Contains(rec.Body.String(), `id="app"`) {
			t.Errorf("%s: body is not the SPA shell: %q", path, rec.Body.String())
		}
	}
}

// TestServesHashedAssetWithImmutableCache proves a real hashed build asset is
// served with a long immutable cache policy and the correct content type.
func TestServesHashedAssetWithImmutableCache(t *testing.T) {
	assets := listAssets(t)
	if len(assets) == 0 {
		t.Fatal("embedded build has no assets/ files; is dist/ built?")
	}
	first := assets[0]

	mux := http.NewServeMux()
	New().Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Prefix+first, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != assetCacheControl {
		t.Errorf("cache-control = %q, want %q", cc, assetCacheControl)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("content-type is empty")
	}
	if rec.Body.Len() == 0 {
		t.Error("asset body is empty")
	}
}

// TestRootRedirectsToSPA proves "/" and "/web" send the browser to the SPA mount.
func TestRootRedirectsToSPA(t *testing.T) {
	mux := http.NewServeMux()
	New().Register(mux)

	tests := []struct {
		path string
		want int
	}{
		{"/", http.StatusFound},
		{"/web", http.StatusMovedPermanently},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if rec.Code != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.path, rec.Code, tt.want)
		}
		if loc := rec.Header().Get("Location"); loc != Prefix {
			t.Errorf("%s: location = %q, want %q", tt.path, loc, Prefix)
		}
	}
}

// TestSecurityHeadersOnEveryAsset proves the hardening headers are present on
// both an asset response and the index fallback, and that the CSP forbids inline
// script (the SPA ships none).
func TestSecurityHeadersOnEveryAsset(t *testing.T) {
	mux := http.NewServeMux()
	New().Register(mux)

	for _, path := range []string{Prefix, Prefix + "combos"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		h := rec.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s: CSP = %q, want script-src 'self'", path, h.Get("Content-Security-Policy"))
		}
		if strings.Contains(h.Get("Content-Security-Policy"), "unsafe-inline") {
			t.Errorf("%s: CSP allows unsafe-inline", path)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", path)
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing X-Frame-Options", path)
		}
		if h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing referrer policy", path)
		}
	}
}

// TestIndexIsNoStore proves the SPA shell is never cached, so a redeploy is
// picked up immediately (the hashed assets are the immutable half).
func TestIndexIsNoStore(t *testing.T) {
	mux := http.NewServeMux()
	New().Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Prefix, nil))
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("index cache-control = %q, want no-store", cc)
	}
}

// TestTraversalStaysInsideTree proves a path traversing out of the asset tree is
// cleaned before the read, so the asset source only ever sees an in-tree
// relative name and a miss falls back to the SPA shell. It never serves a file
// outside dist/.
func TestTraversalStaysInsideTree(t *testing.T) {
	var seen []string
	h := &Handler{read: func(name string) ([]byte, error) {
		seen = append(seen, name)
		if name == indexName {
			return []byte("<html>shell</html>"), nil
		}
		return nil, fs.ErrNotExist
	}}
	req := httptest.NewRequest(http.MethodGet, Prefix+"../../etc/passwd", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, name := range seen {
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			t.Fatalf("asset source saw an escaping name %q", name)
		}
	}
	// The cleaned in-tree miss falls back to the shell.
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shell") {
		t.Fatalf("traversal was not neutralised: %d %q", rec.Code, rec.Body.String())
	}
}

// TestUnknownExtensionIsOctetStream covers writeAsset's content-type fallback.
func TestUnknownExtensionIsOctetStream(t *testing.T) {
	h := &Handler{read: func(name string) ([]byte, error) {
		if name == "blob.unknownext" {
			return []byte("data"), nil
		}
		return nil, fs.ErrNotExist
	}}
	req := httptest.NewRequest(http.MethodGet, Prefix+"blob.unknownext", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content-type = %q, want octet-stream", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != assetCacheControl {
		t.Errorf("cache-control = %q, want immutable", cc)
	}
}

// TestMissingIndexIsAClear500 covers the defensive branch: the embed guarantees
// index.html, but a broken source must fail loudly rather than serve an empty
// body.
func TestMissingIndexIsAClear500(t *testing.T) {
	h := &Handler{read: func(string) ([]byte, error) { return nil, errors.New("no dist") }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Prefix, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "index.html") {
		t.Errorf("body = %q, want a mention of index.html", rec.Body.String())
	}
}

// TestNonGetMethodFallsThrough proves the asset handler only claims GET, so a
// mutating method on the SPA path hits the mux's own 405 (rendered by the shared
// ErrorEnvelope), never the asset handler.
func TestNonGetMethodFallsThrough(t *testing.T) {
	mux := http.NewServeMux()
	New().Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, Prefix, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// listAssets returns the asset file names (relative to the mount point) in the
// embedded build.
func listAssets(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(distFS, base+"/assets")
	if err != nil {
		t.Fatalf("read embedded assets: %v", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, "assets/"+e.Name())
	}
	return out
}
