package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// webRequest drives a request against the FULL assembled handler (LocalOnly +
// Host/Origin guards + the mux), so the smoke proves the SPA inherits the
// catch-all protection exactly like the management API does.
func webRequest(t *testing.T, a *App, method, path, remote, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	req.Host = host
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	return rec
}

// TestWebUIServedThroughHandler is the F5.2b smoke: the embedded SPA shell is
// served at /web/ from the real assembled handler, so the embed, the mount and
// the mux route are exercised together (not just the webui unit).
func TestWebUIServedThroughHandler(t *testing.T) {
	a := buildTestApp(t)

	rec := webRequest(t, a, http.MethodGet, "/web/", "127.0.0.1:1234", "127.0.0.1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="app"`) {
		t.Errorf("body is not the SPA shell: %q", body)
	}
	// The shell references the hashed build asset under the mount point, which
	// is what proves the Vite base and the Go mount agree.
	if !strings.Contains(body, "/web/assets/") {
		t.Errorf("shell does not reference /web/assets/: %q", body)
	}
	// A deep client route falls back to the same shell (hash router).
	deep := webRequest(t, a, http.MethodGet, "/web/combos", "127.0.0.1:1234", "127.0.0.1")
	if deep.Code != http.StatusOK || !strings.Contains(deep.Body.String(), `id="app"`) {
		t.Errorf("deep route did not fall back to the shell: %d %q", deep.Code, deep.Body.String())
	}
}

// TestWebUIIsLocalOnlyProtected is the security half of the smoke: a
// non-loopback peer is refused with 403 BEFORE the asset is served, proving the
// SPA is covered by the same catch-all LocalOnly as /api/mgmt/*. No token is
// involved: the rejection is unconditional.
func TestWebUIIsLocalOnlyProtected(t *testing.T) {
	a := buildTestApp(t)

	for _, path := range []string{"/web/", "/web/combos"} {
		rec := webRequest(t, a, http.MethodGet, path, "198.51.100.9:4444", "evil.test")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: remote status = %d, want 403", path, rec.Code)
		}
	}
}

// TestWebUIHostRebindingRejected proves the anti-DNS-rebinding HostGuard covers
// the SPA: a loopback peer with a public Host header is refused, so a rebinding
// page cannot read the GUI either.
func TestWebUIHostRebindingRejected(t *testing.T) {
	a := buildTestApp(t)
	rec := webRequest(t, a, http.MethodGet, "/web/", "127.0.0.1:1234", "evil.com")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestWebUIIndexIsNoStore proves the shell carries the no-store policy through
// the full handler, matching the webui unit's guarantee.
func TestWebUIIndexIsNoStore(t *testing.T) {
	a := buildTestApp(t)
	rec := webRequest(t, a, http.MethodGet, "/web/", "127.0.0.1:1234", "127.0.0.1")
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control = %q, want no-store", cc)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("CSP = %q", rec.Header().Get("Content-Security-Policy"))
	}
}
