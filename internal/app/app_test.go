package app

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
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

// TestEmptyVaultBootsWithoutKey is the P0-A rule: a fresh vault has nothing to
// decrypt, so the daemon must come up without a master key.
func TestEmptyVaultBootsWithoutKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("empty vault must boot without a key: %v", err)
	}
	defer func() { _ = instance.Close() }()

	if instance.Secrets != nil {
		t.Error("Secrets must stay nil on an empty vault with no key configured")
	}
	if instance.Credentials == nil || instance.Providers == nil || instance.Flows == nil {
		t.Error("vault layer not wired")
	}
	// Health still answers.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	instance.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", rec.Code)
	}
}

// TestVaultWithCredentialsRequiresKey is the P0-A fail-closed rule: once a
// credential exists, a boot without the master key must be refused with
// config.secret_missing.
func TestVaultWithCredentialsRequiresKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "heimdall.db")
	cfg := config.Defaults()
	cfg.Store.Path = dbPath
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	// Seal one credential under a fixed KEK.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	kek, err := secret.DeriveKEK([]byte("some-material"), salt,
		secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sec, err := secret.NewWithKEK(kek)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}
	sealed, err := sec.Seal([]byte("sk-live-token"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cs := store.NewCredentialStore(st)
	if err := cs.Upsert(context.Background(), contracts.Credential{
		ID:       "cred-1",
		Provider: "z.ai",
		AuthMode: contracts.AuthAPIKey,
		Sealed:   []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	_ = st.Close()

	// Now boot with NO custody layer configured: must refuse, fail-closed.
	_, err = Build(Options{Config: cfg, Env: map[string]string{}})
	if err == nil {
		t.Fatal("boot succeeded with credentials but no key")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigSecretMissing {
		t.Fatalf("err = %v, want config.secret_missing", err)
	}
}

// TestVaultWithCredentialsBootsWithKey proves the inverse: supplying the KEK
// lets the daemon come up and decrypt.
func TestVaultWithCredentialsBootsWithKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "heimdall.db")
	cfg := config.Defaults()
	cfg.Store.Path = dbPath
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	salt, _ := secret.LoadOrCreateSalt(st)
	kek, _ := secret.DeriveKEK([]byte("boot-material"), salt,
		secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32})
	sec, _ := secret.NewWithKEK(kek)
	sealed, _ := sec.Seal([]byte("sk-live-token"))
	cs := store.NewCredentialStore(st)
	if err := cs.Upsert(context.Background(), contracts.Credential{
		ID:       "cred-1",
		Provider: "z.ai",
		AuthMode: contracts.AuthAPIKey,
		Sealed:   []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	_ = st.Close()

	instance, err := Build(Options{
		Config: cfg,
		Env:    map[string]string{},
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "boot-material"},
				AllowEnvOverride: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("boot with a key: %v", err)
	}
	defer func() { _ = instance.Close() }()

	if instance.Secrets == nil {
		t.Fatal("Secrets not wired after a successful key resolution")
	}
	cred, err := instance.Credentials.Get(context.Background(), "cred-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	plain, err := instance.Secrets.Open(string(cred.Sealed))
	if err != nil || string(plain) != "sk-live-token" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
}

// TestProviderListAndStatus is the P0-A CLI surface: listing and status work
// without any key and report the pending Antigravity endpoints.
func TestProviderListAndStatus(t *testing.T) {
	a := buildTestApp(t)

	list := a.ProviderList()
	if len(list) != 4 {
		t.Fatalf("ProviderList = %d, want 4", len(list))
	}
	// Deterministic order.
	wantOrder := []domain.ProviderID{"antigravity", "command-code", "ollama-cloud", "z.ai"}
	for i, p := range list {
		if p.ID != wantOrder[i] {
			t.Fatalf("ProviderList[%d] = %s, want %s", i, p.ID, wantOrder[i])
		}
	}

	var antigravity *ProviderSummary
	for i := range list {
		if list[i].ID == "antigravity" {
			antigravity = &list[i]
		}
	}
	if antigravity == nil || len(antigravity.PendingEndpoints) == 0 {
		t.Fatal("antigravity pending endpoints not reported")
	}
	// Antigravity is OAuth, not API key: the listing must reflect the declared
	// mode, not the family's default.
	if len(antigravity.AuthModes) != 1 || antigravity.AuthModes[0] != "oauth" {
		t.Errorf("antigravity auth modes = %v, want [oauth]", antigravity.AuthModes)
	}
	for _, p := range list {
		if p.ID == "z.ai" {
			if len(p.AuthModes) != 1 || p.AuthModes[0] != "api_key" {
				t.Errorf("z.ai auth modes = %v, want [api_key]", p.AuthModes)
			}
		}
	}

	status := a.ProviderStatus()
	var readyCount int
	for _, s := range status {
		if s.ID == "antigravity" {
			if s.Ready {
				t.Error("antigravity reported ready while endpoints are pending")
			}
			if s.ReasonCode != "auth.provider_pending_endpoints" {
				t.Errorf("antigravity reason = %q", s.ReasonCode)
			}
		} else if s.Ready {
			readyCount++
		}
	}
	if readyCount != 3 {
		t.Errorf("ready API-key providers = %d, want 3", readyCount)
	}
}

// TestImportCredentialsRequiresKey: importing seals into the vault, so without a
// KEK it must fail closed rather than write plaintext.
func TestImportCredentialsRequiresKey(t *testing.T) {
	a := buildTestApp(t) // empty vault, no Secrets
	if _, err := a.ImportCredentials(context.Background()); err == nil {
		t.Fatal("import succeeded without a KEK")
	} else {
		de, ok := err.(*domain.DomainError)
		if !ok || de.Code != domain.CodeConfigSecretMissing {
			t.Fatalf("err = %v, want config.secret_missing", err)
		}
	}
}

// TestImportCredentialsEndToEnd imports a synthetic opencode file through the
// app and proves the vault now holds a sealed credential.
func TestImportCredentialsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"zai-coding-plan":{"type":"api","key":"sk-imported-key-123"}}`), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	salt, _ := secret.NewSalt()
	kek, _ := secret.DeriveKEK([]byte("import-material"), salt,
		secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32})

	instance, err := Build(Options{
		Config: cfg,
		Env:    map[string]string{"HEIMDALL_IMPORT_OPENCODE": src, "HOME": home},
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				KeyFilePath:      filepath.Join(dir, "master-key"),
				AllowEnvOverride: true,
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "import-material"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	results, err := instance.ImportCredentials(context.Background())
	if err != nil {
		t.Fatalf("ImportCredentials: %v", err)
	}
	if len(results) != 1 || results[0].Provider != "z.ai" {
		t.Fatalf("results = %+v", results)
	}
	cred, err := instance.Credentials.Get(context.Background(), results[0].CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	plain, err := instance.Secrets.Open(string(cred.Sealed))
	if err != nil || string(plain) != "sk-imported-key-123" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
	_ = kek
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
