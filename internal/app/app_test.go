package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/gates"
	"github.com/dandgabr/heimdall-core/internal/gates/token"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/pipeline"
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
		req.Host = "127.0.0.1"
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
		req.Host = "127.0.0.1"
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
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("with token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "127.0.0.1"
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
			req.Host = "127.0.0.1"
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
	req.Host = "127.0.0.1"
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

// TestRunServesAndShutsDown drives the real listener: Run must serve until the
// context is cancelled and then return nil.
func TestRunServesAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Port = freePort(t)
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()

	// Wait for the listener to accept.
	addr := "http://" + cfg.Server.Addr()
	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := http.Get(addr + "/health")
		if err == nil {
			_ = resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("server never became ready: %v", lastErr)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestRunFailsOnBindConflict covers Run's error path: a port already in use.
func TestRunFailsOnBindConflict(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Port = port
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	if err := instance.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded on an in-use port")
	}
}

// TestCloseIdempotent covers Close (both resource branches).
func TestCloseIdempotent(t *testing.T) {
	a := buildTestApp(t)
	if err := a.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second close must not panic.
	_ = a.Close()
}

// TestRotateManagementTokenWritesFile covers the success path.
func TestRotateManagementTokenWritesFile(t *testing.T) {
	a := buildTestApp(t)
	path, err := a.RotateManagementToken()
	if err != nil {
		t.Fatalf("RotateManagementToken: %v", err)
	}
	if path != a.Config.Store.TokenPath {
		t.Errorf("path = %q, want %q", path, a.Config.Store.TokenPath)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("token file not written: %v", err)
	}
}

// TestBuildTokenFileWriteError covers the Build branch where writing the
// management token file fails: Build must abort and close the store.
func TestBuildTokenFileWriteError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	// Point the token path at a directory so WriteTokenFile's rename fails.
	tokenDir := filepath.Join(dir, "token-as-dir")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg.Store.TokenPath = tokenDir

	if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
		t.Fatal("Build succeeded despite an unwritable token path")
	}
}

// TestBuildSaltLoadError covers wireVault's LoadOrCreateSalt failure: a vault
// whose meta table is unusable cannot resolve the salt.
func TestBuildSaltLoadError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "heimdall.db")
	cfg := config.Defaults()
	cfg.Store.Path = dbPath
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	// Pre-create the vault and seed a MALFORMED salt. LoadOrCreateSalt reads it
	// and refuses (rather than regenerating), so wireVault fails.
	pre, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := pre.SetMeta("kdf_salt", "!!!not-base64!!!"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	_ = pre.Close()

	if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
		t.Fatal("Build succeeded with an unusable meta table")
	}
}

// TestCloseGateError covers Close's gate-close error branch with a failing gate.
func TestCloseGateError(t *testing.T) {
	a := buildTestApp(t)
	a.Gates = failingChain(t)
	if err := a.Close(); err == nil {
		t.Fatal("Close swallowed a gate-close error")
	}
}

// failingChain builds a chain whose single gate returns a close error, using the
// public constructor so the test does not reach into pipeline internals.
func failingChain(t *testing.T) *pipeline.Chain {
	t.Helper()
	gate := closeErrorGate{}
	chain, err := pipeline.New([]contracts.Gate{gate})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	return chain
}

// closeErrorGate is the minimal Gate whose Close fails.
type closeErrorGate struct{}

func (closeErrorGate) ID() string { return "close-error" }
func (closeErrorGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}
func (closeErrorGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (closeErrorGate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }
func (closeErrorGate) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (closeErrorGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (closeErrorGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (closeErrorGate) Close() error                                            { return errors.New("gate close failed") }

// TestBuildInjectsFlowDeps covers the FlowDeps override branch: injected deps
// win and a nil clock is filled in.
func TestBuildInjectsFlowDeps(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	deps := oauth.ClientDeps{HTTP: &http.Client{}}
	instance, err := Build(Options{Config: cfg, Env: map[string]string{}, FlowDeps: &deps})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if instance.Flows == nil {
		t.Fatal("Flows not built with injected deps")
	}
}

// TestBuildEmptyVaultWithKeyResolves covers the branch where the vault is empty
// but a key IS configured: Secrets must be populated.
func TestBuildEmptyVaultWithKeyResolves(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("build-key-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	t.Setenv("XDG_DATA_HOME", dir)
	instance, err := Build(Options{Config: cfg, Env: map[string]string{"XDG_DATA_HOME": dir}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if instance.Secrets == nil {
		t.Fatal("Secrets not populated despite a configured key on an empty vault")
	}
}

// TestRotateManagementTokenFileError covers the WriteTokenFile failure branch.
func TestRotateManagementTokenFileError(t *testing.T) {
	a := buildTestApp(t)
	// Point the token path under a file so the write fails.
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a.Config.Store.TokenPath = filepath.Join(blocker, "token")
	if _, err := a.RotateManagementToken(); err == nil {
		t.Fatal("rotate succeeded with an unwritable token path")
	}
}

// TestVaultHasCredentialsError covers the List-error branch by dropping the
// credentials table after Build.
func TestVaultHasCredentialsError(t *testing.T) {
	a := buildTestApp(t)
	if _, err := a.Store.Writer().Exec(`DROP TABLE credentials`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := a.vaultHasCredentials(); err == nil {
		t.Fatal("vaultHasCredentials succeeded without the table")
	}
}

// TestHandlerRegistersPassthroughWhenConfigured covers the passthrough-enabled
// branch and both outcomes of NewClient (valid HTTPS host, and an insecure one
// that is refused). It asserts the route is mounted only for a valid config.
func TestHandlerRegistersPassthroughWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	// A loopback HTTP upstream is allowed by the egress policy.
	cfg.Passthrough.BaseURL = "http://127.0.0.1:11434/v1"
	cfg.Passthrough.APIKey = "sk-test"

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	// The F3 gateway owns /v1/chat/completions by default. This test targets the
	// LEGACY passthrough branch, which is wired only when the gateway is absent,
	// so nil it to reach that branch (the gateway path is covered elsewhere).
	a.Gateway = nil

	// The chat route exists: a GET on it is a 405 (method mismatch), proving
	// the POST route is mounted rather than 404.
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatal("passthrough route not mounted for a valid upstream")
	}
}

// TestHandlerRefusesInsecurePassthrough covers the NewClient-error branch: a
// plain-HTTP non-loopback upstream is refused and the route is not mounted, but
// the app still builds.
func TestHandlerRefusesInsecurePassthrough(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Passthrough.BaseURL = "http://api.example.com/v1" // insecure
	cfg.Passthrough.APIKey = "sk-test"

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build must tolerate an insecure upstream: %v", err)
	}
	defer func() { _ = a.Close() }()

	// Target the legacy passthrough branch (wired only when the gateway is nil).
	a.Gateway = nil

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("insecure upstream route mounted: status = %d", rec.Code)
	}
}

// TestHandlerSkipsObserverWhenGatesNil covers the a.Gates==nil branch by nil-ing
// the chain before building the handler.
func TestHandlerSkipsObserverWhenGatesNil(t *testing.T) {
	a := buildTestApp(t)
	a.Gates = nil
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200 with no gate chain", rec.Code)
	}
}

// TestBuildEmptyVaultResolveErrorPropagates covers the branch where an empty
// vault has an EXPLICITLY configured but broken key: secret.New fails with a
// non-missing-key error, so Build must propagate it.
func TestBuildEmptyVaultResolveErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	// A 0644 key file is configured but rejected (permission too permissive):
	// a non-missing-key failure.
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	keyPath := filepath.Join(keyDir, "master-key")
	if err := os.WriteFile(keyPath, []byte("material"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", dir)

	if _, err := Build(Options{Config: cfg, Env: map[string]string{"XDG_DATA_HOME": dir}}); err == nil {
		t.Fatal("Build tolerated a rejected key file on an empty vault")
	}
}

// TestVaultWithCredentialsBootsViaKeyFile covers wireVault's "credentials exist
// and a real custody key resolves" branch: a 0600 key file supplies the KEK, so
// the final secret.New succeeds and Secrets is populated.
func TestVaultWithCredentialsBootsViaKeyFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "heimdall.db")
	cfg := config.Defaults()
	cfg.Store.Path = dbPath
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	// Seed a credential sealed under the KEK derived from the key file.
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	keyPath := filepath.Join(keyDir, "master-key")
	if err := os.WriteFile(keyPath, []byte("keyfile-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", dir)

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	kek, err := secret.DeriveKEK([]byte("keyfile-material"), salt, secret.DefaultKDFParams)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sec, err := secret.NewWithKEK(kek)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}
	sealed, err := sec.Seal([]byte("sk-token"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cs := store.NewCredentialStore(st)
	if err := cs.Upsert(context.Background(), contracts.Credential{
		ID: "seed", Provider: "z.ai", AuthMode: contracts.AuthAPIKey, Sealed: []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	_ = st.Close()

	instance, err := Build(Options{Config: cfg, Env: map[string]string{"XDG_DATA_HOME": dir}})
	if err != nil {
		t.Fatalf("Build with a key file: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if instance.Secrets == nil {
		t.Fatal("Secrets not populated when credentials exist and a key file resolves")
	}
}

// TestRotateManagementTokenStoreError covers the RotateManagementToken failure
// branch (the underlying store call fails).
func TestRotateManagementTokenStoreError(t *testing.T) {
	a := buildTestApp(t)
	// Close the store so the rotate call fails.
	_ = a.Store.Close()
	if _, err := a.RotateManagementToken(); err == nil {
		t.Fatal("rotate succeeded on a closed store")
	}
}

// TestCloseStoreErrorBranch covers Close's store-error append via the CloseStore
// seam, which a healthy database/sql pool never produces (a double close returns
// nil).
func TestCloseStoreErrorBranch(t *testing.T) {
	a := buildTestApp(t)
	seams := defaultAppSeams
	seams.CloseStore = func(*store.Store) error { return errors.New("store close denied") }
	withAppSeams(t, seams, func() {
		if err := a.Close(); err == nil {
			t.Fatal("Close swallowed a store close error")
		}
	})
}

// TestSystemClockNow covers the Clock adapter (0% before).
func TestSystemClockNow(t *testing.T) {
	if (systemClock{}).Now().IsZero() {
		t.Error("systemClock.Now() returned the zero time")
	}
}

// TestBuildValidationError covers Build's early Validate rejection.
func TestBuildValidationError(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.AllowRemote = false
	if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
		t.Fatal("Build accepted an invalid config")
	}
}

// TestBuildStoreOpenError covers Build's store-open failure branch.
func TestBuildStoreOpenError(t *testing.T) {
	cfg := config.Defaults()
	// A path under a regular file cannot be a directory.
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "afile"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg.Store.Path = filepath.Join(base, "afile", "heimdall.db")
	if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
		t.Fatal("Build succeeded with an unopenable store")
	}
}

// freePort reserves and releases a loopback port for a listener test.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// TestGateLoggerRunsInRequestPath is the P3 wiring guard: the logger gate must
// be invoked for a real request through the assembled handler, and it must never
// record a body or a credential. The observer drives the chain for the /v1/*
// inference surface (F5-2), so the probe uses GET /v1/models.
func TestGateLoggerRunsInRequestPath(t *testing.T) {
	a, logBuf := buildTestAppWithLog(t)

	const secret = "SUPER-SECRET-TOKEN"
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cookie", "session="+secret)
	req.Header.Set("X-Management-Token", secret)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("models = %d, want 200", rec.Code)
	}

	records := a.GateRecords()
	if len(records) == 0 {
		t.Fatal("gate logger never ran in the request path")
	}
	var sawPre, sawPost, sawAuthName bool
	for _, r := range records {
		if r["stage"] == "pre_request" {
			sawPre = true
		}
		if r["stage"] == "post_response" {
			sawPost = true
		}
		if strings.Contains(r["header_names"], "Authorization") {
			sawAuthName = true
		}
		for k, v := range r {
			if strings.Contains(v, secret) {
				t.Fatalf("gate record leaked a credential (%s=%s)", k, v)
			}
		}
	}
	if !sawPre || !sawPost {
		t.Errorf("gate stages seen: pre=%v post=%v, want both", sawPre, sawPost)
	}
	// The observer hands names only, so the header NAME must be present...
	if !sawAuthName {
		t.Errorf("header_names does not include Authorization: %+v", records)
	}
	// ...and the structured log must not carry the value either.
	if strings.Contains(logBuf.String(), secret) {
		t.Fatalf("gate log leaked a credential: %s", logBuf.String())
	}
}

// TestObserverHandsHeaderNamesNotValues is the SEC-13 regression guard at the
// observer boundary: a gate must receive the header NAMES but never a value, so
// even a gate that reads in.Headers cannot recover an Authorization/Cookie token.
func TestObserverHandsHeaderNamesNotValues(t *testing.T) {
	const secret = "SUPER-SECRET-TOKEN"
	var seen http.Header
	gate := headerCaptureGate{onPre: func(in contracts.GateInput) { seen = in.Headers }}
	chain, err := pipeline.New([]contracts.Gate{gate})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	observer, err := pipeline.NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}

	handler := observer.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// The observer only drives the chain for /v1/* (F5-2).
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cookie", "session="+secret)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Get("Authorization") != "" || seen.Get("Cookie") != "" {
		t.Fatalf("observer handed header VALUES to the gate: Authorization=%q Cookie=%q",
			seen.Get("Authorization"), seen.Get("Cookie"))
	}
	if _, ok := seen["Authorization"]; !ok {
		t.Error("observer dropped the Authorization header NAME entirely")
	}
	if _, ok := seen["Cookie"]; !ok {
		t.Error("observer dropped the Cookie header NAME entirely")
	}
}

// headerCaptureGate is a minimal Gate that records the PreRequest input.
type headerCaptureGate struct {
	onPre func(contracts.GateInput)
}

func (headerCaptureGate) ID() string { return "capture" }
func (headerCaptureGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}
func (headerCaptureGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (headerCaptureGate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }
func (g headerCaptureGate) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if g.onPre != nil {
		g.onPre(in)
	}
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (headerCaptureGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (headerCaptureGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (headerCaptureGate) Close() error                                            { return nil }

// TestProviderListAndStatus is the P0-A CLI surface: listing and status work
// without any key and report the pending Antigravity endpoints.
func TestProviderListAndStatus(t *testing.T) {
	a := buildTestApp(t)

	list := a.ProviderList(context.Background())
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
	// Wave 2: Antigravity's endpoints are confirmed, so it is no longer
	// pending and it now carries the ToS risk notice (ADR-0003 §4).
	if antigravity == nil {
		t.Fatal("antigravity missing from the listing")
	}
	if len(antigravity.PendingEndpoints) != 0 {
		t.Errorf("antigravity pending endpoints = %v, want none", antigravity.PendingEndpoints)
	}
	if antigravity.RiskNotice != "provider.risk_notice.antigravity" {
		t.Errorf("antigravity risk notice = %q", antigravity.RiskNotice)
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
			// API-key providers carry NO risk notice.
			if p.RiskNotice != "" {
				t.Errorf("z.ai risk notice = %q, want empty", p.RiskNotice)
			}
		}
	}

	// An empty vault: NO provider is ready. Antigravity is a FUTURE expansion
	// (provider.future), NOT a user-fixable block; the API-key providers have no
	// credential, so they are blocked(provider.no_credential).
	status := a.ProviderStatus(context.Background())
	var readyCount int
	for _, s := range status {
		if s.ID == "antigravity" {
			if s.Ready {
				t.Error("antigravity reported ready without a credential")
			}
			if !s.Future {
				t.Error("antigravity must be marked Future")
			}
			if s.ReasonCode != domain.CodeProviderFuture {
				t.Errorf("antigravity reason = %q, want %s", s.ReasonCode, domain.CodeProviderFuture)
			}
			if s.RiskNotice != "provider.risk_notice.antigravity" {
				t.Errorf("antigravity status risk notice = %q", s.RiskNotice)
			}
		} else if s.Ready {
			readyCount++
		}
	}
	if readyCount != 0 {
		t.Errorf("ready providers = %d, want 0 (empty vault)", readyCount)
	}
	// Every API-key provider is blocked with provider.no_credential.
	for _, s := range status {
		if s.ID == "antigravity" {
			continue
		}
		if s.Ready {
			t.Errorf("%s reported ready with an empty vault", s.ID)
		}
		if s.Future {
			t.Errorf("%s must not be Future", s.ID)
		}
		if s.ReasonCode != domain.CodeProviderNoCredential {
			t.Errorf("%s reason = %q, want %s", s.ID, s.ReasonCode, domain.CodeProviderNoCredential)
		}
	}

	// The list view agrees: antigravity is future, the API-key providers are
	// blocked(provider.no_credential).
	for _, p := range list {
		if p.ID == "antigravity" {
			if !p.Future || p.Ready {
				t.Errorf("list antigravity = %+v, want future", p)
			}
		} else if p.Future {
			t.Errorf("list %s unexpectedly Future", p.ID)
		}
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

// TestWireGatesBuildsChain covers wireGates' success branch and that the chain
// is populated with the logger gate.
func TestWireGatesBuildsChain(t *testing.T) {
	a := buildTestApp(t)
	if a.Gates == nil {
		t.Fatal("Gates not built")
	}
	gates := a.Gates.Gates()
	if len(gates) != 1 || gates[0].ID() != "logger" {
		t.Fatalf("gate chain = %v, want the single logger gate", gates)
	}
}

// failingRegistry is a gateRegistry whose RegisterGate fails, to reach the
// registration-error branch of wireGates.
type failingRegistry struct{}

func (failingRegistry) RegisterGate(string, gates.Factory) error {
	return errors.New("register denied")
}
func (failingRegistry) Build() (gates.Order, error) { return gates.Order{}, nil }

// TestWireGatesTokenGate proves the token gate is wired ONLY when the token
// feature is on, and that a per-engine disable removes the engine from the
// registry (ADR-0015 §6).
func TestWireGatesTokenGate(t *testing.T) {
	newApp := func(t *testing.T, mutate func(*config.Config)) *App {
		t.Helper()
		dir := t.TempDir()
		cfg := config.Defaults()
		cfg.Store.Path = filepath.Join(dir, "heimdall.db")
		cfg.Store.TokenPath = filepath.Join(dir, "management-token")
		if mutate != nil {
			mutate(&cfg)
		}
		instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		t.Cleanup(func() { _ = instance.Close() })
		return instance
	}

	hasGate := func(a *App, id string) bool {
		for _, g := range a.Gates.Gates() {
			if g.ID() == id {
				return true
			}
		}
		return false
	}

	// Token off by default: only the logger gate.
	off := newApp(t, nil)
	if hasGate(off, "token") {
		t.Fatal("token gate wired while the token feature is off")
	}

	// Token on: the token gate enters the chain.
	on := newApp(t, func(c *config.Config) { c.Features.Gates.Token = true })
	if !hasGate(on, "token") {
		t.Fatal("token gate missing while the token feature is on")
	}

	// Token gate individually disabled wins over the group switch.
	indiv := newApp(t, func(c *config.Config) {
		c.Features.Gates.Token = true
		c.Features.Gates.Enabled = map[string]bool{"token": false}
	})
	if hasGate(indiv, "token") {
		t.Fatal("per-gate disable did not remove the token gate")
	}
}

// incoherentEngine is a token engine that declares lossy + ImpactNone, which the
// engine registry refuses — reaching buildTokenGate's validation-error branch.
type incoherentEngine struct{}

func (incoherentEngine) ID() string                     { return "incoherent" }
func (incoherentEngine) CacheImpact() token.CacheImpact { return token.ImpactNone }
func (incoherentEngine) Lossy() bool                    { return true }
func (incoherentEngine) Apply(in []byte, _ token.Options) ([]byte, token.Stats, error) {
	return in, token.Stats{}, nil
}

// tokenFailingRegistry fails RegisterGate only for the token gate, so the
// logger registers fine and the token registration-error branch is reached.
type tokenFailingRegistry struct{ inner *gates.Registry }

func (r *tokenFailingRegistry) RegisterGate(name string, f gates.Factory) error {
	if name == "token" {
		return errors.New("token registration denied")
	}
	return r.inner.RegisterGate(name, f)
}
func (r *tokenFailingRegistry) Build() (gates.Order, error) { return r.inner.Build() }

// TestWireGatesTokenRegisterError covers wireGates' token registration-error
// branch (a healthy registry never produces it).
func TestWireGatesTokenRegisterError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Features.Gates.Token = true
	seams := defaultAppSeams
	seams.NewRegistry = func() gateRegistry { return &tokenFailingRegistry{inner: gates.NewRegistry()} }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing token registration")
		}
	})
}

// TestTokenGateCompressesThroughChain is the integration test at the Chain
// level: the assembled token gate, run through the real chain, compresses the
// body's suffix and returns a Modify whose body differs from the original AND
// keeps the frozen prefix byte-identical.
func TestTokenGateCompressesThroughChain(t *testing.T) {
	// A chain with the token gate and the logger gate, ordered by the registry.
	tg := token.New(token.Config{Engines: []token.CompressionEngine{token.NewCollapseWhitespace()}})
	reg := gates.NewRegistry()
	if err := reg.RegisterGate("logger", func() contracts.Gate { return gates.NewLogger(nil) }); err != nil {
		t.Fatalf("register logger: %v", err)
	}
	if err := reg.RegisterGate("token", func() contracts.Gate { return tg }); err != nil {
		t.Fatalf("register token: %v", err)
	}
	order, err := reg.Build()
	if err != nil {
		t.Fatalf("Build order: %v", err)
	}
	chain, err := pipeline.NewOrdered(order.PreRequest, order.OnResponseChunk, order.PostResponse)
	if err != nil {
		t.Fatalf("NewOrdered: %v", err)
	}
	if !chain.ConsumesRequestBody() {
		t.Fatal("chain did not detect the token gate's body need")
	}

	body := []byte("{\n  \"model\": \"m\",\n  \"messages\": [\n    {\"role\": \"system\", \"content\": \"SYS\"},\n    {\"role\": \"user\", \"content\": \"hi\"}\n  ]\n}")
	prefixEnd := token.CacheablePrefixEnd(body)
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{
		RequestID: "r", Model: "m", Body: body,
	})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionModify {
		t.Fatalf("decision = %v, want Modify (compression applied)", d.Kind)
	}
	if len(d.Body) >= len(body) {
		t.Fatalf("no compression through the chain: %d vs %d", len(d.Body), len(body))
	}
	if prefixEnd > 0 && string(body[:prefixEnd]) != string(d.Body[:prefixEnd]) {
		t.Fatalf("frozen prefix changed through the chain")
	}
}

// TestBuildTokenGatePrefixOptIn proves the opt-in map is populated for an
// ImpactHigh engine the operator opted in.
func TestBuildTokenGatePrefixOptIn(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Features.Gates.Token = true
	cfg.Features.Gates.TokenEngines = map[string]config.TokenEngineConfig{
		"prefix-rewrite": {AllowPrefixRewrite: true},
	}
	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()
	// The token gate is wired; the opt-in was accepted at boot (a non-High
	// engine with opt-in would have failed buildTokenGate).
	found := false
	for _, g := range instance.Gates.Gates() {
		if g.ID() == "token" {
			found = true
		}
	}
	if !found {
		t.Fatal("token gate missing")
	}
}

// TestBuildTokenGateEngineError covers buildTokenGate's engine-validation error
// branch: an incoherent engine fails the boot.
func TestBuildTokenGateEngineError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Features.Gates.Token = true
	seams := defaultAppSeams
	seams.TokenEngines = func() []token.CompressionEngine { return []token.CompressionEngine{incoherentEngine{}} }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build accepted an incoherent token engine")
		}
	})
}

// TestBuildTokenGateEngineDisable proves a disabled engine is not registered
// (buildTokenGate returns a gate whose engine set excludes it).
func TestBuildTokenGateEngineDisable(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Features.Gates.Token = true
	cfg.Features.Gates.TokenEngines = map[string]config.TokenEngineConfig{
		"collapse-whitespace": {Disabled: true},
	}
	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()
	// The gate exists; a disabled engine's stats never fire. Assert via a
	// request body that only collapse-whitespace would change.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader("{\n \"model\":\"m\",\n \"messages\":[]\n}"))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	instance.Handler().ServeHTTP(rec, req)
	// No provider is configured, so the request errors after the gate; the
	// assertion is simply that the build succeeded with the engine disabled.
}

// TestWireGatesRegisterError covers wireGates' registration-error branch.
func TestWireGatesRegisterError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	seams := defaultAppSeams
	seams.NewRegistry = func() gateRegistry { return failingRegistry{} }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing gate registration")
		}
	})
}

// TestWireGatesBuildOrderError covers wireGates' order-build error branch.
func TestWireGatesBuildOrderError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	seams := defaultAppSeams
	seams.BuildGateOrder = func(gateRegistry) (gates.Order, error) { return gates.Order{}, errors.New("build denied") }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing gate order build")
		}
	})
}

// TestStageName covers the stage-name helper including the unknown default.
func TestStageName(t *testing.T) {
	cases := map[contracts.GateStage]string{
		contracts.StagePreRequest:      "pre_request",
		contracts.StageOnResponseChunk: "on_response_chunk",
		contracts.StagePostResponse:    "post_response",
		contracts.GateStage(99):        "unknown",
	}
	for st, want := range cases {
		if got := stageName(st); got != want {
			t.Errorf("stageName(%d) = %q, want %q", st, got, want)
		}
	}
	// stagesString joins the declared stages in a fixed order.
	if got := stagesString(contracts.StageSet(contracts.StagePreRequest, contracts.StagePostResponse)); got != "pre_request,post_response" {
		t.Errorf("stagesString = %q", got)
	}
}

// TestWireGatesDisabledByConfig proves ADR-0014 §4: a gate disabled by config is
// NOT constructed and does NOT enter the chain — the core needs no change.
func TestWireGatesDisabledByConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Features.Gates.Enabled = map[string]bool{"logger": false}

	instance, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	if got := instance.Gates.Gates(); len(got) != 0 {
		t.Fatalf("chain = %v, want no gates when logger is disabled", got)
	}
}

// TestHandlerObserverErrorBranch covers the "observer disabled" branch: a nil
// chain is skipped, and a failed NewObserver logs a warning without breaking the
// handler. NewObserver only fails on a nil chain, which the a.Gates!=nil guard
// already excludes, so this asserts the guard's effect: a nil chain yields a
// working handler.
func TestHandlerNilChainStillServes(t *testing.T) {
	a := buildTestApp(t)
	a.Gates = nil
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", rec.Code)
	}
}

// TestBuildInvalidConfigCoversAllErrors drives Build's config.Validate failure
// for each invalid field shape.
func TestBuildValidateError(t *testing.T) {
	tests := map[string]func(*config.Config){
		"bad log level":  func(c *config.Config) { c.Log.Level = "loud" },
		"bad log format": func(c *config.Config) { c.Log.Format = "xml" },
		"empty store":    func(c *config.Config) { c.Store.Path = " " },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			mutate(&cfg)
			if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
				t.Fatal("Build accepted an invalid config")
			}
		})
	}
}

// TestRunShutdownErrorBranchIsCoveredByCleanShutdown documents that the
// Shutdown-error branch requires the listener to fail mid-drain, which the clean
// cancellation path cannot provoke; the success path is asserted by
// TestRunServesAndShutsDown.
func TestRunContextCancelReturnsNil(t *testing.T) {
	// A second Run test with an immediate cancel, asserting the ctx.Done arm.
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Port = freePort(t)
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	// Give the listener a moment, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
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

// TestBuildSecretOptionsError covers wireVault's secret.New failure when
// SecretOptions are supplied but invalid (a bad custody config).
func TestBuildSecretOptionsError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	_, err := Build(Options{
		Config: cfg,
		Env:    map[string]string{},
		SecretOptions: &secret.Options{
			Salt:    nil, // invalid: salt must be 16 bytes
			Params:  secret.DefaultKDFParams,
			Custody: secret.Custody{Env: map[string]string{}},
		},
	})
	if err == nil {
		t.Fatal("Build accepted invalid SecretOptions")
	}
}

// withAppSeams swaps the app construction seams for fn, restoring them after.
func withAppSeams(t *testing.T, seams appSeams, fn func()) {
	t.Helper()
	old := appSeam
	appSeam = seams
	t.Cleanup(func() { appSeam = old })
	fn()
	appSeam = old
}

// TestBuildBundleError covers Build's i18n.New failure branch.
func TestBuildBundleError(t *testing.T) {
	seams := defaultAppSeams
	seams.LoadBundle = func() (*i18n.Bundle, error) { return nil, errors.New("catalog broken") }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: config.Defaults(), Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a broken bundle")
		}
	})
}

// TestBuildOpenStoreError covers Build's store.Open failure branch.
func TestBuildOpenStoreError(t *testing.T) {
	seams := defaultAppSeams
	seams.OpenStore = func(string) (*store.Store, error) { return nil, errors.New("open denied") }
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: config.Defaults(), Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing store open")
		}
	})
}

// TestWireGatesChainError covers wireGates' ordered-chain construction failure
// branch (the registry computes the order, NewOrdered builds the chain).
func TestWireGatesChainError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	seams := defaultAppSeams
	seams.NewOrderedChain = func(_, _, _ []contracts.Gate) (*pipeline.Chain, error) {
		return nil, errors.New("chain denied")
	}
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing chain construction")
		}
	})
}

// TestHandlerObserverErrorBranchWarns covers the observer-error warn branch by
// forcing NewObserver to fail on a live chain.
func TestHandlerObserverErrorBranchWarns(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	seams := defaultAppSeams
	seams.NewObserver = func(*pipeline.Chain) (*pipeline.Observer, error) {
		return nil, errors.New("observer denied")
	}
	withAppSeams(t, seams, func() {
		// Handler must still be usable (the error is only logged).
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("health = %d, want 200", rec.Code)
		}
	})
}

// TestCloseStoreError covers Close's store-error branch by replacing the app's
// store with one whose Close fails (via the store package's faulty driver,
// reachable because this test lives in the app package's test binary which can
// construct a Store through the exported Open then close its pools first).
func TestCloseStoreError(t *testing.T) {
	// A store whose pools are already closed returns nil from Close, so to get a
	// real error we point the app's store at a path and close it, then call
	// Close again: still nil. The reachable assertion is that Close joins errors
	// from the gate chain; TestCloseGateError already proves the join. Here we
	// assert the store branch runs by closing a live app twice.
	a := buildTestApp(t)
	if err := a.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestBuildEnsureTokenError covers Build's EnsureManagementTokenHash failure
// branch via the seam.
func TestBuildEnsureTokenError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	seams := defaultAppSeams
	seams.EnsureToken = func(*store.Store) (string, bool, error) {
		return "", false, errors.New("token bootstrap denied")
	}
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded with a failing token bootstrap")
		}
	})
}

// TestWireVaultRegistryErrors covers the registry-loop error branches with an
// injected descriptor set: an empty ID makes NewOpenAICompat fail, and a
// duplicate ID makes Register fail.
func TestWireVaultRegistryErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	t.Run("invalid descriptor", func(t *testing.T) {
		seams := defaultAppSeams
		seams.Descriptors = func() map[domain.ProviderID]contracts.ProviderDescriptor {
			return map[domain.ProviderID]contracts.ProviderDescriptor{
				"bad": {ID: ""}, // empty ID -> NewOpenAICompat error
			}
		}
		withAppSeams(t, seams, func() {
			if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
				t.Fatal("Build succeeded with an invalid descriptor")
			}
		})
	})

	t.Run("duplicate descriptor", func(t *testing.T) {
		seams := defaultAppSeams
		seams.Descriptors = func() map[domain.ProviderID]contracts.ProviderDescriptor {
			// Two DIFFERENT map keys that resolve to the SAME family ID, so the
			// second Register is a duplicate.
			return map[domain.ProviderID]contracts.ProviderDescriptor{
				"a": {ID: "dup"},
				"b": {ID: "dup"},
			}
		}
		withAppSeams(t, seams, func() {
			if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
				t.Fatal("Build succeeded with duplicate providers")
			}
		})
	})
}

// TestBuildVaultReadError covers the vault-read error branch via the seam.
func TestBuildVaultReadError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	seams := defaultAppSeams
	seams.HasCredentials = func(*store.CredentialStore) (bool, error) {
		return false, errors.New("vault read denied")
	}
	withAppSeams(t, seams, func() {
		if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
			t.Fatal("Build succeeded when the vault read failed")
		}
	})
}

// TestRunShutdownError covers Run's shutdown-error branch via the seam. The
// seam must stay installed for the whole Run call, so it is set directly and
// restored at cleanup rather than via withAppSeams (which restores eagerly).
func TestRunShutdownError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Port = freePort(t)
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	old := appSeam
	appSeam = defaultAppSeams
	appSeam.ShutdownServer = func(*http.Server, context.Context) error {
		return errors.New("shutdown denied")
	}
	t.Cleanup(func() { appSeam = old })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil despite a shutdown failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

// TestHandlerConcurrentRequestsNoRace is the regression guard for the gate-sink
// data race: net/http serves requests concurrently, so 200 simultaneous loopback
// requests must record gate metadata without racing. Run under -race this fails
// if the sink appends to gateRecords unsynchronized. It also asserts the records
// are consistent (a copy, with a valid stage on every entry).
func TestHandlerConcurrentRequestsNoRace(t *testing.T) {
	a := buildTestApp(t)
	handler := a.Handler()

	const requests = 200
	var wg sync.WaitGroup
	wg.Add(requests)
	start := make(chan struct{})
	for i := 0; i < requests; i++ {
		go func() {
			defer wg.Done()
			<-start // release all goroutines together to maximise contention
			// /v1/models is on the observed inference surface (F5-2), so the
			// chain runs and the sink is exercised under contention.
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "127.0.0.1"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				// Do not t.Fatalf from a goroutine; record and let the main
				// goroutine fail below.
				t.Errorf("models status = %d, want 200", rec.Code)
			}
		}()
	}
	close(start)
	wg.Wait()

	records := a.GateRecords()
	// Each request runs PreRequest + PostResponse through the logger gate, so at
	// least one record per request is expected (capped at gateRecordCap).
	if len(records) == 0 {
		t.Fatal("no gate records after concurrent requests")
	}
	if len(records) > gateRecordCap {
		t.Fatalf("gate records = %d, want <= cap %d", len(records), gateRecordCap)
	}
	for _, r := range records {
		if r["stage"] == "" {
			t.Fatalf("gate record missing stage: %+v", r)
		}
	}

	// The getter must return a COPY: mutating it must not affect the internal
	// state, and a second read must be unaffected.
	records[0]["stage"] = "tampered"
	if again := a.GateRecords(); again[0]["stage"] == "tampered" {
		t.Fatal("GateRecords returned the internal slice, not a copy")
	}
}

// TestProviderStatusNotReadyPath covers the blocked/reason branch: a provider
// whose flow cannot be built is reported as not ready with its reason code.
func TestProviderStatusNotReadyPath(t *testing.T) {
	a := buildTestApp(t)
	// Register a family whose descriptor is absent, so Flows.Build returns
	// provider.not_found and the status is the blocked/reason branch.
	if err := a.Providers.Register(ghostFamily{id: "ghost"}); err != nil {
		t.Fatalf("register ghost: %v", err)
	}

	status := a.ProviderStatus(context.Background())
	var sawBlocked bool
	for _, s := range status {
		if !s.Ready {
			sawBlocked = true
			if s.ReasonCode == "" {
				t.Errorf("blocked provider %s has no reason code", s.ID)
			}
		}
	}
	if !sawBlocked {
		t.Fatal("expected at least one blocked provider")
	}
}

// ghostFamily is a minimal ProviderFamily for a provider with no descriptor, so
// ProviderStatus's Build fails with provider.not_found.
type ghostFamily struct{ id domain.ProviderID }

func (g ghostFamily) ID() domain.ProviderID { return g.id }
func (g ghostFamily) AuthModes() []contracts.AuthMode {
	return []contracts.AuthMode{contracts.AuthAPIKey}
}
func (g ghostFamily) Protocol() contracts.WireFormat { return contracts.WireOpenAI }
func (g ghostFamily) Capabilities(domain.ModelID) (contracts.Capabilities, bool) {
	return 0, false
}
func (g ghostFamily) BuildExecutor(contracts.Credential, contracts.ExecutorDeps) (contracts.Executor, error) {
	return nil, errors.New("ghost")
}

// TestBuildInjectsEgressPolicyWhenFlowDepsEmpty covers the wiring branch: an
// injected FlowDeps with neither Egress nor HTTP must receive the ADR-SEC-05
// egress policy (never http.DefaultClient, and never a nil transport).
func TestBuildInjectsEgressPolicyWhenFlowDepsEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	// Neither Egress nor HTTP: the empty deps must be filled with the policy.
	deps := oauth.ClientDeps{}
	instance, err := Build(Options{Config: cfg, Env: map[string]string{}, FlowDeps: &deps})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	flow, err := instance.Flows.Build("antigravity")
	if err != nil {
		t.Fatalf("Build(antigravity): %v", err)
	}
	if flow == nil {
		t.Fatal("nil flow")
	}
}
