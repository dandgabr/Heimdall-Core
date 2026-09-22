package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/providers"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// buildProviderApp builds an app whose z.ai provider points at srvURL (loopback,
// explicitly allowed). No credential is seeded; use seedCredential for that.
func buildProviderApp(t *testing.T, srvURL string) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Providers = []config.ProviderConfig{{
		// AllowLoopback only for a loopback literal (a non-loopback URL with the
		// flag set is rejected by Config.Validate, which is the point).
		ID: "z.ai", BaseURL: srvURL, AuthHeader: "bearer",
		AllowLoopback: strings.HasPrefix(srvURL, "http://127.0.0.1"), Enabled: true,
	}}

	salt, _ := secret.NewSalt()
	instance, err := Build(Options{
		Config: cfg,
		Env:    map[string]string{},
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				KeyFilePath:      filepath.Join(dir, "master-key"),
				AllowEnvOverride: true,
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "provider-test-material"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// seedCredential seals plaintext and upserts a credential into the vault.
func seedCredential(t *testing.T, a *App, id domain.CredentialID, mode contracts.AuthMode, plaintext string) {
	t.Helper()
	seedCredentialFor(t, a, "z.ai", id, mode, plaintext)
}

// seedCredentialFor seals plaintext and upserts a credential for a chosen
// provider; used by the readiness tests for z.ai and antigravity.
func seedCredentialFor(t *testing.T, a *App, provider domain.ProviderID, id domain.CredentialID, mode contracts.AuthMode, plaintext string) {
	t.Helper()
	sealed, err := a.Secrets.Seal([]byte(plaintext))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := a.Credentials.Upsert(context.Background(), contracts.Credential{
		ID: id, Provider: provider, AuthMode: mode, Sealed: []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
}

// TestProviderTestHappyPath is the end-to-end integration: the executor is built
// with the configured BaseURL, injects the Bearer token, probes GET /models and
// reports the upstream status.
func TestProviderTestHappyPath(t *testing.T) {
	var hits int32
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	a := buildProviderApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	res, err := a.ProviderTest(context.Background(), "z.ai")
	if err != nil {
		t.Fatalf("ProviderTest: %v", err)
	}
	if res.Provider != "z.ai" || res.CredentialID != "cred-z" || res.Status != http.StatusOK {
		t.Fatalf("result = %+v", res)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if gotAuth != "Bearer sk-live-secret-key" {
		t.Fatalf("Authorization = %q, want the injected bearer", gotAuth)
	}
	if gotPath != "/v1/models" {
		t.Fatalf("path = %q, want /v1/models (configured base url + /models)", gotPath)
	}
}

// TestProviderTestAPIKeyHeader proves auth_header=x-api-key selects that header.
func TestProviderTestAPIKeyHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := buildProviderAppWithHeader(t, srv.URL+"/v1", "x-api-key")
	seedCredential(t, a, "c", contracts.AuthAPIKey, "KEY-XYZ")
	if _, err := a.ProviderTest(context.Background(), "z.ai"); err != nil {
		t.Fatalf("ProviderTest: %v", err)
	}
	if gotKey != "KEY-XYZ" {
		t.Fatalf("x-api-key = %q, want KEY-XYZ", gotKey)
	}
}

// TestProviderTestNoCredential covers the no-credential branch.
func TestProviderTestNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	a := buildProviderApp(t, srv.URL+"/v1") // no credential upserted
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeProviderNoCredential) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNoCredential)
	}
}

// TestProviderTestOAuthLoginRequired covers the OAuth credential branch.
func TestProviderTestOAuthLoginRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	a := buildProviderApp(t, srv.URL+"/v1")
	seedCredential(t, a, "oauth", contracts.AuthOAuth, "oauth-blob")
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeProviderLoginRequired) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderLoginRequired)
	}
}

// TestProviderTestUpstreamErrors covers the ADR-0002 mapping for an upstream
// failure at the probe.
func TestProviderTestUpstreamErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantCode string
	}{
		{"401 credential invalid", http.StatusUnauthorized, domain.CodeUpstreamUnavailable},
		{"500 provider retryable", http.StatusInternalServerError, domain.CodeUpstreamUnavailable},
		{"400 request", http.StatusBadRequest, domain.CodeBadUpstreamResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("upstream detail must not leak"))
			}))
			defer srv.Close()
			a := buildProviderApp(t, srv.URL+"/v1")
			seedCredential(t, a, "c", contracts.AuthAPIKey, "sk-key-12345678")
			res, err := a.ProviderTest(context.Background(), "z.ai")
			if err == nil {
				t.Fatal("expected an upstream error")
			}
			if !hasCode(err, tt.wantCode) {
				t.Fatalf("err = %v, want %s", err, tt.wantCode)
			}
			if res.Status != tt.status {
				t.Fatalf("status = %d, want %d", res.Status, tt.status)
			}
			if strings.Contains(err.Error(), "upstream detail") {
				t.Fatal("the upstream body leaked into the error")
			}
		})
	}
}

// TestProviderTestUnknownProvider covers the registry lookup failure.
func TestProviderTestUnknownProvider(t *testing.T) {
	a := buildTestApp(t)
	_, err := a.ProviderTest(context.Background(), "does-not-exist")
	if !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNotFound)
	}
}

// TestProviderTestFamilyWithoutBaseURL covers the BuildExecutor refusal: a
// provider registered with no base_url cannot be probed.
func TestProviderTestFamilyWithoutBaseURL(t *testing.T) {
	a := buildTestApp(t)                     // default config: no providers block, so no base_url
	sealed, _ := a.Secrets.Seal([]byte("k")) // test app may lack Secrets; guard below
	if a.Secrets == nil {
		t.Skip("test app has no secret store")
	}
	if err := a.Credentials.Upsert(context.Background(), contracts.Credential{
		ID: "c", Provider: "z.ai", AuthMode: contracts.AuthAPIKey, Sealed: []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeProviderInvalid) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderInvalid)
	}
}

// hasCode is a local copy of the suite's helper.
func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}

// buildProviderAppWithHeader builds a provider app with a chosen auth_header.
func buildProviderAppWithHeader(t *testing.T, srvURL, header string) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Providers = []config.ProviderConfig{{
		ID: "z.ai", BaseURL: srvURL, AuthHeader: header,
		AllowLoopback: strings.HasPrefix(srvURL, "http://127.0.0.1"), Enabled: true,
	}}
	salt, _ := secret.NewSalt()
	a, err := Build(Options{Config: cfg, Env: map[string]string{}, SecretOptions: &secret.Options{
		Salt: salt, Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
		Custody: secret.Custody{KeyFilePath: filepath.Join(dir, "k"), AllowEnvOverride: true,
			Env: map[string]string{"HEIMDALL_MASTER_KEY": "m"}},
	}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// stubFamily is a minimal ProviderFamily for the ProviderTest branch tests.
type stubFamily struct {
	id   domain.ProviderID
	exec contracts.Executor
	err  error
}

func (s stubFamily) ID() domain.ProviderID { return s.id }
func (s stubFamily) AuthModes() []contracts.AuthMode {
	return []contracts.AuthMode{contracts.AuthAPIKey}
}
func (s stubFamily) Protocol() contracts.WireFormat { return contracts.WireOpenAI }
func (s stubFamily) Capabilities(domain.ModelID) (contracts.Capabilities, bool) {
	return 0, false
}
func (s stubFamily) BuildExecutor(contracts.Credential, contracts.ExecutorDeps) (contracts.Executor, error) {
	return s.exec, s.err
}

// nonProbeExecutor is a contracts.Executor without the Probe method.
type nonProbeExecutor struct{}

func (nonProbeExecutor) Family() domain.ProviderID { return "stub" }
func (nonProbeExecutor) Do(context.Context, contracts.WireRequest, contracts.Credential) (contracts.WireResponse, error) {
	return contracts.WireResponse{}, nil
}
func (nonProbeExecutor) DoStream(context.Context, contracts.WireRequest, contracts.Credential) (contracts.Stream, error) {
	return nil, nil
}
func (nonProbeExecutor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

// TestProviderTestSecretStoreNil covers the KEK-absent refusal.
func TestProviderTestSecretStoreNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	a := buildProviderApp(t, srv.URL+"/v1")
	seedCredential(t, a, "c", contracts.AuthAPIKey, "k")
	a.Secrets = nil // simulate a vault with no KEK
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeConfigSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeConfigSecretMissing)
	}
}

// TestProviderTestBuildExecutorError covers the family build failure.
func TestProviderTestBuildExecutorError(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	seedCredential(t, a, "c", contracts.AuthAPIKey, "k")
	a.Providers = providers.NewRegistry()
	if err := a.Providers.Register(stubFamily{id: "z.ai", err: domain.New(domain.CodeProviderInvalid, domain.WithHTTPStatus(500))}); err != nil {
		t.Fatalf("register: %v", err)
	}
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeProviderInvalid) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderInvalid)
	}
}

// TestProviderTestNonProbeExecutor covers the executor-without-Probe refusal.
func TestProviderTestNonProbeExecutor(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	seedCredential(t, a, "c", contracts.AuthAPIKey, "k")
	a.Providers = providers.NewRegistry()
	if err := a.Providers.Register(stubFamily{id: "z.ai", exec: nonProbeExecutor{}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	_, err := a.ProviderTest(context.Background(), "z.ai")
	if !hasCode(err, domain.CodeProviderNoExecutor) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNoExecutor)
	}
}

// TestCredentialForListError covers the store-list failure branch.
func TestCredentialForListError(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	_ = a.Store.Close() // break the underlying pool
	if _, err := a.credentialFor(context.Background(), "z.ai"); err == nil {
		t.Fatal("expected the list error")
	}
}

// TestDomainIDGen covers the IDGen adapter.
func TestDomainIDGen(t *testing.T) {
	if (domainIDGen{}).NewRequestID() == "" {
		t.Fatal("NewRequestID returned empty")
	}
}

// --- ProviderStatus/ProviderList readiness (P0: no misleading "ready") ---

// readyByID indexes a status slice by provider.
func readyByID(list []ProviderStatus) map[domain.ProviderID]ProviderStatus {
	m := make(map[domain.ProviderID]ProviderStatus, len(list))
	for _, s := range list {
		m[s.ID] = s
	}
	return m
}

// (a) Empty vault: every provider is not-ready with the correct code.
func TestProviderReadinessEmptyVault(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1") // vault has Secrets but no credential
	status := readyByID(a.ProviderStatus(context.Background()))

	// OAuth without login -> provider.login_required.
	if s := status["antigravity"]; s.Ready || s.ReasonCode != domain.CodeProviderLoginRequired {
		t.Errorf("antigravity = %+v, want blocked(provider.login_required)", s)
	}
	// API-key without credential -> provider.no_credential.
	for _, id := range []domain.ProviderID{"z.ai", "ollama-cloud", "command-code"} {
		if s := status[id]; s.Ready || s.ReasonCode != domain.CodeProviderNoCredential {
			t.Errorf("%s = %+v, want blocked(provider.no_credential)", id, s)
		}
	}

	// The list view uses the SAME rule.
	for _, p := range a.ProviderList(context.Background()) {
		if p.Ready {
			t.Errorf("provider list reported %s ready with an empty vault", p.ID)
		}
		if p.ID == "antigravity" && p.ReasonCode != domain.CodeProviderLoginRequired {
			t.Errorf("list antigravity reason = %q", p.ReasonCode)
		}
		if p.ID == "z.ai" && p.ReasonCode != domain.CodeProviderNoCredential {
			t.Errorf("list z.ai reason = %q", p.ReasonCode)
		}
	}
}

// (b) API-key with a seeded credential -> ready.
func TestProviderReadinessAPIKeyWithCredential(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	seedCredential(t, a, "c", contracts.AuthAPIKey, "sk-key")
	status := readyByID(a.ProviderStatus(context.Background()))
	if s := status["z.ai"]; !s.Ready || s.ReasonCode != "" {
		t.Fatalf("z.ai = %+v, want ready", s)
	}

	// The list agrees.
	var z ProviderSummary
	for _, p := range a.ProviderList(context.Background()) {
		if p.ID == "z.ai" {
			z = p
		}
	}
	if !z.Ready {
		t.Fatalf("list z.ai = %+v, want ready", z)
	}
}

// (c) OAuth with a synthetic credential in the vault -> ready (the credential
// exists, so the provider is usable; this does not prove a live token).
func TestProviderReadinessOAuthWithCredential(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	seedCredentialFor(t, a, "antigravity", "ag", contracts.AuthOAuth, "oauth-blob")
	status := readyByID(a.ProviderStatus(context.Background()))
	if s := status["antigravity"]; !s.Ready || s.ReasonCode != "" {
		t.Fatalf("antigravity = %+v, want ready with a stored credential", s)
	}
}

// (d) OAuth without a credential -> blocked(provider.login_required) even
// though the endpoints are configured (no pending fields).
func TestProviderReadinessOAuthWithoutCredential(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	status := readyByID(a.ProviderStatus(context.Background()))
	s := status["antigravity"]
	if s.Ready {
		t.Fatal("antigravity must not be ready without a credential")
	}
	if s.ReasonCode != domain.CodeProviderLoginRequired {
		t.Fatalf("antigravity reason = %q, want %s", s.ReasonCode, domain.CodeProviderLoginRequired)
	}
	// Endpoints are confirmed, so the reason is NOT the pending code.
	if len(auth.PendingFields("antigravity")) != 0 {
		t.Fatal("antigravity unexpectedly has pending endpoints")
	}
}

// A credential whose mode the family does not support is blocked with
// credential.invalid_auth_mode.
func TestProviderReadinessUnsupportedMode(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	// z.ai is API-key only; seed an OAuth credential for it.
	seedCredential(t, a, "c", contracts.AuthOAuth, "oauth-blob")
	s := readyByID(a.ProviderStatus(context.Background()))["z.ai"]
	if s.Ready || s.ReasonCode != domain.CodeCredentialInvalidAuthMode {
		t.Fatalf("z.ai = %+v, want blocked(credential.invalid_auth_mode)", s)
	}
}

// A vault read error makes every provider not-ready (never falsely ready).
func TestProviderReadinessListError(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	_ = a.Store.Close() // break the underlying pool
	status := a.ProviderStatus(context.Background())
	for _, s := range status {
		if s.Ready {
			t.Errorf("%s reported ready despite a vault read error", s.ID)
		}
	}
}

// TestDomainErrorCode covers both branches of the helper: a DomainError yields
// its code, a plain error yields "".
func TestDomainErrorCode(t *testing.T) {
	if got := domainErrorCode(domain.New(domain.CodeProviderNoCredential, domain.WithHTTPStatus(404))); got != domain.CodeProviderNoCredential {
		t.Fatalf("domainErrorCode(domain err) = %q", got)
	}
	if got := domainErrorCode(errors.New("plain")); got != "" {
		t.Fatalf("domainErrorCode(plain) = %q, want empty", got)
	}
}
