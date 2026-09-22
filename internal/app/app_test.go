package app

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// buildTestApp builds an app whose token file lives in the temp dir.
func buildTestApp(t *testing.T) *App {
	t.Helper()
	instance, _ := buildTestAppWithLog(t)
	return instance
}

// buildTestAppWithLog also returns the log buffer so a test can assert the
// secret never reached the structured logger.
func buildTestAppWithLog(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Log.Level = "debug"

	var logBuf bytes.Buffer
	instance, err := Build(Options{
		Config:    cfg,
		Env:       map[string]string{},
		LogOutput: &logBuf,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance, &logBuf
}

// readTokenFile returns the plaintext token the app wrote on first boot.
func readTokenFile(t *testing.T, a *App) string {
	t.Helper()
	body, err := os.ReadFile(a.Config.Store.TokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	return strings.TrimSpace(string(body))
}

func TestHealthAndModels(t *testing.T) {
	a := buildTestApp(t)

	t.Run("health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "api.health_ok") {
			t.Errorf("body = %s", rec.Body.String())
		}
	})

	t.Run("models empty list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"data":[]`) {
			t.Errorf("body = %s", rec.Body.String())
		}
	})
}

func TestMgmtPingRequiresToken(t *testing.T) {
	a := buildTestApp(t)
	token := readTokenFile(t, a)

	t.Run("no token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("with token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

// TestManagementTokenNeverLogged is the P0-3 regression guard: the 256-bit
// management token must not appear in stdout, the structured logger or the
// database. Only the file path is reported.
func TestManagementTokenNeverLogged(t *testing.T) {
	a, logBuf := buildTestAppWithLog(t)
	token := readTokenFile(t, a)

	if token == "" {
		t.Fatal("token file is empty")
	}
	if strings.Contains(logBuf.String(), token) {
		t.Fatalf("management token leaked into the structured log: %s", logBuf.String())
	}

	// The database must not contain the plaintext in any meta value.
	for _, key := range []string{store.ManagementTokenKey, store.ManagementTokenHashKey} {
		if v, found, _ := a.Store.GetMeta(key); found && strings.Contains(v, token) {
			t.Errorf("plaintext token persisted under meta[%q]", key)
		}
	}

	// The log must reference the file, not the value.
	if !strings.Contains(logBuf.String(), a.Config.Store.TokenPath) {
		t.Errorf("log does not mention the token file path: %s", logBuf.String())
	}
}

func TestRotateManagementTokenInvalidatesPrevious(t *testing.T) {
	a, _ := buildTestAppWithLog(t)
	first := readTokenFile(t, a)

	path, err := a.RotateManagementToken()
	if err != nil {
		t.Fatalf("RotateManagementToken: %v", err)
	}
	if path != a.Config.Store.TokenPath {
		t.Errorf("rotate path = %q, want %q", path, a.Config.Store.TokenPath)
	}
	second := readTokenFile(t, a)
	if second == first {
		t.Fatal("token file unchanged after rotation")
	}

	if a.Store.VerifyManagementToken(first) {
		t.Error("previous token still verifies after rotation")
	}
	if !a.Store.VerifyManagementToken(second) {
		t.Error("new token does not verify after rotation")
	}
}

// TestCatchAllProtectsEveryRoute is the end-to-end companion to the middleware
// unit test: the assembled handler graph rejects a remote peer on a route the
// app itself registered, proving LocalOnly wraps the whole mux.
func TestCatchAllProtectsEveryRoute(t *testing.T) {
	a := buildTestApp(t)
	token := readTokenFile(t, a)

	for _, path := range []string{"/health", "/v1/models", "/api/mgmt/ping"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "198.51.100.9:4444"
		// Even a valid token must not help a remote peer.
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, rec.Code)
		}
	}
}

// TestMuxErrorsUseI18nEnvelope is the R2 regression guard: a 404 or 405 emitted
// by the mux itself must be the same JSON {error:{code}} envelope as every
// handler, not the stdlib plain-text page.
func TestMuxErrorsUseI18nEnvelope(t *testing.T) {
	a := buildTestApp(t)

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
		wantKey  string
	}{
		{"unknown route", http.MethodGet, "/does-not-exist", http.StatusNotFound, "error.not_found"},
		{"wrong method", http.MethodPost, "/health", http.StatusMethodNotAllowed, "error.method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			a.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("content-type = %q, want application/json", ct)
			}
			if rec.Header().Get("X-Request-ID") == "" {
				t.Error("X-Request-ID header missing")
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantKey) {
				t.Errorf("body = %q, want code %q", body, tt.wantKey)
			}
			if strings.Contains(body, "page not found") || strings.Contains(body, "Method Not Allowed") {
				t.Errorf("plain-text stdlib body leaked: %q", body)
			}
			// A JSON body must not carry the text/plain X-Content-Type-Options
			// header the mux sets for its canned responses.
			if rec.Header().Get("X-Content-Type-Options") != "" {
				t.Errorf("unexpected X-Content-Type-Options: %q", rec.Header().Get("X-Content-Type-Options"))
			}
		})
	}
}

// TestServeOnIPv6Loopback is the N1 integration guard: with host "::1" the
// address composed by config.Addr() must be bindable and answer on
// http://[::1]:<port>. It is skipped when the machine has no usable IPv6
// loopback.
func TestServeOnIPv6Loopback(t *testing.T) {
	// Reserve the port and keep the listener: this avoids a TOCTOU race where
	// the port could be taken between reserving and rebinding it.
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no usable IPv6 loopback: %v", err)
	}
	tcpAddr, ok := probe.Addr().(*net.TCPAddr)
	if !ok {
		_ = probe.Close()
		t.Fatal("listener address is not TCP")
	}
	port := tcpAddr.Port
	_ = probe.Close()

	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Host = "::1"
	cfg.Server.Port = port
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	// This is the exact string the real server binds. Binding it proves the
	// composition is valid (the old "::1:8787" failed here with "too many
	// colons in address").
	addr := instance.server.Addr
	if !strings.HasPrefix(addr, "[::1]:") {
		t.Fatalf("composed address = %q, want a bracketed IPv6 host", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(%q): %v", addr, err)
	}
	srv := &http.Server{Handler: instance.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// ln.Addr() is already bracketed, e.g. "[::1]:43123".
	url := "http://" + ln.Addr().String() + "/health"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
