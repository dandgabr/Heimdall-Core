package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/providers"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// testAntigravitySecret is a NON-SECRET placeholder injected into the config so
// the Antigravity OAuth flow builds in tests. It is deliberately not shaped like
// a real Google client secret, so it cannot be mistaken for one (and the guard
// test that scans for real-secret patterns leaves it alone).
const testAntigravitySecret = "test-only-client-secret-not-real"

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
	}, {
		// Antigravity's OAuth flow requires a client secret that is NO LONGER
		// hardcoded; the operator supplies it. The readiness tests inject one so
		// the flow builds (the missing-secret fail-closed path is covered
		// separately). A disabled entry needs no base_url.
		ID: "antigravity", ClientSecret: testAntigravitySecret,
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

// TestProviderTestOAuthWithoutCredentialIsLoginRequired is the BD02-3/BD02-4
// acceptance test: an OAuth provider WITHOUT a credential reports the SAME
// code `provider status` reports for the state (provider.login_required),
// never provider.no_credential with its misleading add-key advice.
func TestProviderTestOAuthWithoutCredentialIsLoginRequired(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1") // Antigravity secret injected, empty vault
	_, err := a.ProviderTest(context.Background(), "antigravity")
	if !hasCode(err, domain.CodeProviderLoginRequired) {
		t.Fatalf("err = %v, want %s (aligned with provider status)", err, domain.CodeProviderLoginRequired)
	}
	// The message must be rendered without a literal placeholder.
	b := i18n.MustNew()
	if msg := b.FormatDomainError(err, "en"); strings.ContainsAny(msg, "{}") {
		t.Fatalf("message has a literal placeholder: %q", msg)
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

	// Antigravity is OAuth with a configured client secret, so the flow builds
	// and the missing piece is the credential: blocked(provider.login_required),
	// the user-fixable state `heimdall login` resolves (BD-02).
	if s := status["antigravity"]; s.Ready || s.Future || s.ReasonCode != domain.CodeProviderLoginRequired {
		t.Errorf("antigravity = %+v, want blocked(provider.login_required)", s)
	}
	// API-key without credential -> provider.no_credential.
	for _, id := range []domain.ProviderID{"z.ai", "ollama-cloud", "command-code"} {
		if s := status[id]; s.Ready || s.Future || s.ReasonCode != domain.CodeProviderNoCredential {
			t.Errorf("%s = %+v, want blocked(provider.no_credential)", id, s)
		}
	}

	// The list view uses the SAME rule.
	for _, p := range a.ProviderList(context.Background()) {
		if p.Ready {
			t.Errorf("provider list reported %s ready with an empty vault", p.ID)
		}
		if p.ID == "antigravity" {
			if p.Future || p.ReasonCode != domain.CodeProviderLoginRequired {
				t.Errorf("list antigravity = %+v, want blocked(login_required)", p)
			}
		} else if p.Future {
			t.Errorf("list %s unexpectedly Future", p.ID)
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

// (c) OAuth with a stored credential -> ready (BD-02: the descriptor is no
// longer Future, so readiness is purely credential-driven).
func TestProviderReadinessOAuthWithCredential(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	seedCredentialFor(t, a, "antigravity", "ag", contracts.AuthOAuth, "oauth-blob")
	status := readyByID(a.ProviderStatus(context.Background()))
	if s := status["antigravity"]; !s.Ready || s.Future || s.ReasonCode != "" {
		t.Fatalf("antigravity = %+v, want ready with a stored credential", s)
	}
}

// (d) OAuth without a credential -> blocked(provider.login_required), even
// though the endpoints are configured and the flow builds.
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

// --- Antigravity live state (BD-02) ---

// TestAntigravityLoginReadyState proves Antigravity left the `future` state:
// the descriptor no longer carries the marker, the provider stays listed with
// its ToS risk notice, and its readiness is credential-driven — without a
// stored credential it is blocked(provider.login_required), the state
// `heimdall login` resolves.
func TestAntigravityLoginReadyState(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1") // secret injected, empty vault

	// Descriptor fact: registered, complete, and NOT future anymore.
	desc, err := auth.Descriptor("antigravity")
	if err != nil {
		t.Fatalf("Descriptor: %v", err)
	}
	if desc.Future || desc.FutureNote != "" {
		t.Fatalf("antigravity descriptor still marked future: %+v", desc)
	}
	if desc.AuthEndpoint == "" || desc.ClientID == "" || !desc.IsObfuscated() || !desc.RequiresClientSecret {
		t.Fatal("removing the future marker must not strip the descriptor's capabilities")
	}

	// Listed (catalog completeness) with the user-fixable blocked state and the
	// risk notice.
	var listed bool
	for _, p := range a.ProviderList(context.Background()) {
		if p.ID != "antigravity" {
			continue
		}
		listed = true
		if p.Future || p.Ready {
			t.Errorf("list antigravity = %+v, want neither future nor ready (empty vault)", p)
		}
		if p.ReasonCode != domain.CodeProviderLoginRequired {
			t.Errorf("list antigravity reason = %q", p.ReasonCode)
		}
		if p.RiskNotice != "provider.risk_notice.antigravity" {
			t.Errorf("list antigravity risk notice = %q", p.RiskNotice)
		}
	}
	if !listed {
		t.Fatal("antigravity is not listed")
	}

	// Status agrees.
	for _, s := range a.ProviderStatus(context.Background()) {
		if s.ID != "antigravity" {
			continue
		}
		if s.Future || s.Ready || s.ReasonCode != domain.CodeProviderLoginRequired {
			t.Errorf("status antigravity = %+v, want blocked(provider.login_required)", s)
		}
		if s.RiskNotice == "" {
			t.Error("status antigravity lost the risk notice")
		}
	}
}

// TestProviderFutureEmptyNote covers the default note when FutureNote is empty.
func TestProviderFutureEmptyNote(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	a.descriptor = func(id domain.ProviderID) (contracts.ProviderDescriptor, error) {
		return contracts.ProviderDescriptor{ID: id, Future: true}, nil
	}
	_, code, reason := a.providerReadiness("z.ai", []contracts.AuthMode{contracts.AuthAPIKey}, nil, nil)
	if code != domain.CodeProviderFuture || reason == "" {
		t.Fatalf("readiness = %q, %q, want provider.future with a default note", code, reason)
	}
}

// --- add-key (Part B) ---

// TestAddAPIKeySealsAndPersists proves the key is sealed (the raw vault bytes do
// NOT contain it) and the credential opens back to the same value.
func TestAddAPIKeySealsAndPersists(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	const key = "sk-live-MANUALLY-ADDED-9f3a2b7c"

	res, err := a.AddAPIKey(context.Background(), "z.ai", "work", key)
	if err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	if res.Provider != "z.ai" || res.Label != "work" || res.CredentialID == "" || res.Upserted {
		t.Fatalf("result = %+v", res)
	}

	// The credential opens back to the key (proof it was sealed correctly).
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	plain, err := a.Secrets.Open(string(cred.Sealed))
	if err != nil || string(plain) != key {
		t.Fatalf("Open = %q, %v", plain, err)
	}

	// The raw DB file must NOT contain the plaintext key.
	raw, err := os.ReadFile(a.Config.Store.Path)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(raw, []byte(key)) {
		t.Fatal("the plaintext key was found in the vault file")
	}
}

// TestAddAPIKeyRefusesOAuth proves an OAuth provider cannot take a static key.
func TestAddAPIKeyRefusesOAuth(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	_, err := a.AddAPIKey(context.Background(), "antigravity", "x", "sk-whatever-12345")
	if !hasCode(err, domain.CodeProviderAPIKeyNotSupported) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderAPIKeyNotSupported)
	}
	// The message must name the provider and its supported modes, with no
	// literal placeholder and no {id} leak.
	b := i18n.MustNew()
	msg := b.FormatDomainError(err, "en")
	if strings.ContainsAny(msg, "{}") {
		t.Fatalf("message has a literal placeholder: %q", msg)
	}
	if !strings.Contains(msg, "antigravity") || !strings.Contains(msg, "oauth") {
		t.Fatalf("message = %q, want the provider and its modes", msg)
	}
	de := err.(*domain.DomainError)
	if de.Params["modes"] != "oauth" || de.Params["provider"] != "antigravity" {
		t.Fatalf("params = %+v", de.Params)
	}
}

// TestAddAPIKeyUnknownProvider covers the registry lookup failure.
func TestAddAPIKeyUnknownProvider(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	if _, err := a.AddAPIKey(context.Background(), "nope", "", "sk-whatever-12345"); !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// TestAddAPIKeyRejectsBadShape covers the offline shape check (empty/short).
func TestAddAPIKeyRejectsBadShape(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	if _, err := a.AddAPIKey(context.Background(), "z.ai", "", "short"); !hasCode(err, domain.CodeAuthKeyInvalidFormat) {
		t.Fatalf("short key err = %v", err)
	}
	if _, err := a.AddAPIKey(context.Background(), "z.ai", "", ""); !hasCode(err, domain.CodeAuthKeyMissing) {
		t.Fatalf("empty key err = %v", err)
	}
}

// TestAddAPIKeyRequiresKEK covers the no-SecretStore refusal.
func TestAddAPIKeyRequiresKEK(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	a.Secrets = nil
	if _, err := a.AddAPIKey(context.Background(), "z.ai", "", "sk-whatever-12345"); !hasCode(err, domain.CodeConfigSecretMissing) {
		t.Fatalf("err = %v", err)
	}
}

// TestAddAPIKeyIdempotent proves re-adding the same provider+label updates the
// same row (no duplicate).
func TestAddAPIKeyIdempotent(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	first, err := a.AddAPIKey(context.Background(), "z.ai", "work", "sk-first-12345678")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := a.AddAPIKey(context.Background(), "z.ai", "work", "sk-second-87654321")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.CredentialID != second.CredentialID {
		t.Fatalf("ids differ: %q vs %q", first.CredentialID, second.CredentialID)
	}
	if first.Upserted || !second.Upserted {
		t.Fatalf("Upserted flags = %v, %v (want false then true)", first.Upserted, second.Upserted)
	}
	creds, err := a.Credentials.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials = %d, want 1 (idempotent)", len(creds))
	}
	// The row now holds the SECOND value.
	plain, _ := a.Secrets.Open(string(creds[0].Sealed))
	if string(plain) != "sk-second-87654321" {
		t.Fatalf("stored value = %q, want the second", plain)
	}
}

// TestAddAPIKeyMakesProviderReady is the integration: after add-key, status is
// ready and provider test can build the executor.
func TestAddAPIKeyMakesProviderReady(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	a := buildProviderApp(t, srv.URL+"/v1")

	before := readyByID(a.ProviderStatus(context.Background()))["z.ai"]
	if before.Ready {
		t.Fatal("z.ai was ready before add-key")
	}
	if _, err := a.AddAPIKey(context.Background(), "z.ai", "", "sk-added-123456789"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	after := readyByID(a.ProviderStatus(context.Background()))["z.ai"]
	if !after.Ready || after.ReasonCode != "" {
		t.Fatalf("z.ai after add-key = %+v, want ready", after)
	}

	res, err := a.ProviderTest(context.Background(), "z.ai")
	if err != nil {
		t.Fatalf("ProviderTest after add-key: %v", err)
	}
	if res.Status != http.StatusOK || gotAuth != "Bearer sk-added-123456789" {
		t.Fatalf("probe = %+v, auth = %q", res, gotAuth)
	}
}

// TestAPIKeyCredentialID covers the deterministic, non-secret id derivation.
func TestAPIKeyCredentialID(t *testing.T) {
	a := apiKeyCredentialID("z.ai", "work")
	b := apiKeyCredentialID("z.ai", "work")
	if a != b {
		t.Fatalf("ids differ: %q vs %q", a, b)
	}
	if a == apiKeyCredentialID("z.ai", "personal") {
		t.Fatal("different labels produced the same id")
	}
	if strings.Contains(string(a), "z.ai") == false {
		t.Fatalf("id %q should be provider-prefixed", a)
	}
}

// TestDescriptorOfFallback covers the nil-descriptor fallback to auth.Descriptor.
func TestDescriptorOfFallback(t *testing.T) {
	a := &App{} // no descriptor seam
	desc, err := a.descriptorOf("z.ai")
	if err != nil || desc.ID != "z.ai" {
		t.Fatalf("descriptorOf fallback = %+v, %v", desc, err)
	}
	if _, err := a.descriptorOf("nope"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

// failingSealer always fails, to cover the seal-error branch.
type failingSealer struct{}

func (failingSealer) Seal([]byte) (string, error) {
	return "", domain.New(domain.CodeSecretDecryptFailed, domain.WithHTTPStatus(500))
}

// TestAddAPIKeySealError covers the seal-failure branch.
func TestAddAPIKeySealError(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	a.sealer = failingSealer{}
	_, err := a.AddAPIKey(context.Background(), "z.ai", "", "sk-whatever-12345")
	if !hasCode(err, domain.CodeCredentialStoreFailed) {
		t.Fatalf("err = %v, want credential.store_failed", err)
	}
}

// TestAddAPIKeyUpsertError covers the store-write failure branch.
func TestAddAPIKeyUpsertError(t *testing.T) {
	a := buildProviderApp(t, "https://x/v1")
	_ = a.Store.Close() // break the write pool
	_, err := a.AddAPIKey(context.Background(), "z.ai", "", "sk-whatever-12345")
	if err == nil {
		t.Fatal("expected the upsert error")
	}
}
