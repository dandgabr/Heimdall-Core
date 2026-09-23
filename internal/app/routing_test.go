package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/providers"
	"github.com/dandgabr/heimdall-core/internal/quota"
	"github.com/dandgabr/heimdall-core/internal/router"
)

// fakeAppClock is a fixed clock for the preflight tests.
type fakeAppClock struct{}

func (fakeAppClock) Now() time.Time { return time.Unix(0, 0) }

// quotaFilterFor builds a quota filter over a reader.
func quotaFilterFor(r contracts.QuotaStateReader) *quota.Filter {
	return quota.NewFilter(r, quota.DefaultConfig(fakeAppClock{}))
}

// TestWireRoutingFailureFailsClosed proves a routing-construction failure closes
// the store and aborts the boot (via the WireRouting seam).
func TestWireRoutingFailureFailsClosed(t *testing.T) {
	orig := appSeam.WireRouting
	defer func() { appSeam.WireRouting = orig }()
	appSeam.WireRouting = func(*App) error { return errors.New("routing boom") }

	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")

	if _, err := Build(Options{Config: cfg, Env: map[string]string{}}); err == nil {
		t.Fatal("Build succeeded despite a routing-construction failure")
	}
}

// TestExecutorFactoryUnknownProvider covers the registry-error branch.
func TestExecutorFactoryUnknownProvider(t *testing.T) {
	f := executorFactory{registry: providers.NewRegistry()}
	_, err := f.Build(context.Background(), contracts.Candidate{Provider: "ghost", Model: "m"}, contracts.Credential{})
	if err == nil {
		t.Fatal("BuildExecutor succeeded for an unknown provider")
	}
}

// TestExecutorFactoryNoSecrets covers the nil-Secrets branch (an AuthNone family
// needs no secret).
func TestExecutorFactoryNoSecrets(t *testing.T) {
	reg := providers.NewRegistry()
	fam, err := providers.NewOpenAICompat(providers.OpenAICompatOptions{
		ID: "local", AuthModes: []contracts.AuthMode{contracts.AuthNone}, BaseURL: "https://example.invalid/v1",
		Models: map[domain.ModelID]providers.ModelCapabilities{"m": {}},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	_ = reg.Register(fam)
	f := executorFactory{registry: reg}
	exec, err := f.Build(context.Background(), contracts.Candidate{Provider: "local", Model: "m"}, contracts.Credential{Provider: "local", AuthMode: contracts.AuthNone})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if exec.Family() != "local" {
		t.Fatalf("family = %s", exec.Family())
	}
}

// TestCredentialSourceFiltersAndOrders proves the adapter lists only a
// provider's credentials, in deterministic id order, filtering unsupported
// modes.
func TestCredentialSourceFiltersAndOrders(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")
	ctx := context.Background()
	seedCredentialFor(t, a, "z.ai", "z-b", contracts.AuthAPIKey, "sk-secret-value-bbbbb")
	seedCredentialFor(t, a, "z.ai", "z-a", contracts.AuthAPIKey, "sk-secret-value-aaaaa")
	// An antigravity OAuth credential would be filtered for z.ai (different
	// provider); seed one for antigravity to prove provider filtering.
	seedCredentialFor(t, a, "antigravity", "anti-1", contracts.AuthOAuth, "oauth-token-value-xxx")

	creds := credentialSource{store: a.Credentials, registry: a.Providers}
	got, err := creds.Credentials(ctx, "z.ai")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(got) != 2 || got[0] != "z-a" || got[1] != "z-b" {
		t.Fatalf("credentials = %v, want [z-a z-b]", got)
	}
}

// TestCredentialsListError covers the store list-error branch.
func TestCredentialsListError(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")
	if _, err := a.Store.Writer().Exec(`DROP TABLE credentials`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	creds := credentialSource{store: a.Credentials, registry: a.Providers}
	if _, err := creds.Credentials(context.Background(), "z.ai"); err == nil {
		t.Fatal("Credentials succeeded without the credentials table")
	}
}

// TestRegistryAuthModesUnknown covers the unknown-provider branch.
func TestRegistryAuthModesUnknown(t *testing.T) {
	creds := credentialSource{registry: providers.NewRegistry()}
	if got := creds.registryAuthModes("ghost"); got != nil {
		t.Fatalf("registryAuthModes(ghost) = %v, want nil", got)
	}
}

// TestPreflightBreakerOpen covers the breaker-denies branch.
func TestPreflightBreakerOpen(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")
	// Force the breaker open for the provider.
	c := contracts.Candidate{Provider: "z.ai", Model: "glm-4.6", Credential: "c1"}
	pk := contracts.KeyFor(contracts.Candidate{Provider: "z.ai"}, contracts.BreakerProvider)
	a.Breaker.RecordKey(pk, breaker.Outcome{Scope: domain.ScopeProvider, Retryable: true})
	p := preflight{quota: a.QuotaFilt, br: a.Breaker}
	ok, reason := p.AllowCandidate(context.Background(), c)
	if ok || reason != "breaker_open" {
		t.Fatalf("AllowCandidate = %v/%q, want false/breaker_open", ok, reason)
	}
}

// TestPreflightAllowsHealthy covers the happy branch.
func TestPreflightAllowsHealthy(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")
	p := preflight{quota: a.QuotaFilt, br: a.Breaker}
	ok, reason := p.AllowCandidate(context.Background(), contracts.Candidate{Provider: "z.ai", Model: "glm-4.6", Credential: "c1"})
	if !ok || reason != "" {
		t.Fatalf("AllowCandidate = %v/%q, want true/empty", ok, reason)
	}
}

// TestWireRoutingRouterError covers the router-construction error branch. The
// app is built first (with the real seam) and the seam is then swapped, so the
// second wireRouting call reaches the error branch.
func TestWireRoutingRouterError(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")

	orig := newRouter
	defer func() { newRouter = orig }()
	newRouter = func(router.ComboLoader, router.ModelCatalog, ...router.Option) (*router.Resolver, error) {
		return nil, errors.New("router boom")
	}
	if err := a.wireRouting(); err == nil {
		t.Fatal("wireRouting tolerated a router construction error")
	}
}

// denyingReader is a QuotaStateReader that reports an exhausted window, so the
// preflight's quota-deny branch is reached.
type denyingReader struct{}

func (denyingReader) Snapshot(context.Context, domain.CredentialID) (contracts.QuotaState, bool) {
	return contracts.QuotaState{Windows: []contracts.QuotaWindow{
		{Kind: contracts.WindowShort, Limit: 100, Remaining: 0},
	}}, true
}

// TestPreflightQuotaDeny covers AllowCandidate's quota-deny branch.
func TestPreflightQuotaDeny(t *testing.T) {
	qf := quotaFilterFor(denyingReader{})
	p := preflight{quota: qf, br: breaker.New(fakeAppClock{})}
	ok, reason := p.AllowCandidate(context.Background(), contracts.Candidate{
		Provider: "z.ai", Model: "glm-4.6", Credential: "c1",
	})
	if ok {
		t.Fatal("AllowCandidate admitted a quota-exhausted candidate")
	}
	if reason != "quota_remaining_below_cutoff" {
		t.Fatalf("reason = %q, want quota_remaining_below_cutoff", reason)
	}
}

// TestQuotaSkipReasonDefensive covers the defensive empty-skip fallback.
func TestQuotaSkipReasonDefensive(t *testing.T) {
	if got := quotaSkipReason(nil); got != "quota_exhausted" {
		t.Fatalf("quotaSkipReason(nil) = %q", got)
	}
	if got := quotaSkipReason([]contracts.Skip{{Reason: "r"}}); got != "r" {
		t.Fatalf("quotaSkipReason = %q", got)
	}
}

// TestPreflightQuotaFailOpen covers the admitted path through the real filter
// with a reader that reports no state.
func TestPreflightQuotaFailOpen(t *testing.T) {
	p := preflight{quota: quota.NewFilter(emptyReader{}, quota.DefaultConfig(fakeAppClock{})), br: breaker.New(fakeAppClock{})}
	ok, reason := p.AllowCandidate(context.Background(), contracts.Candidate{Provider: "z.ai", Model: "m", Credential: "c"})
	if !ok || reason != "" {
		t.Fatalf("AllowCandidate = %v/%q, want true/empty", ok, reason)
	}
}

// emptyReader reports no state (fail-open).
type emptyReader struct{}

func (emptyReader) Snapshot(context.Context, domain.CredentialID) (contracts.QuotaState, bool) {
	return contracts.QuotaState{}, false
}

// TestFamilyModelsSkipsEmpty covers the empty-model skip in familyModels.
func TestFamilyModelsSkipsEmpty(t *testing.T) {
	m := familyModels([]string{"m1", "", "m2"})
	if len(m) != 2 {
		t.Fatalf("familyModels = %v, want 2 entries", m)
	}
	if len(familyModels(nil)) != 0 {
		t.Fatal("familyModels(nil) not empty")
	}
}

// TestBuildFamilyUnknownProtocolFallsBackToOpenAI proves a non-cloudcode dialect
// builds the OpenAI-compatible family.
func TestBuildFamilyDefaultProtocol(t *testing.T) {
	desc := contracts.ProviderDescriptor{ID: "z.ai", Protocol: contracts.WireOpenAI}
	fam, err := buildFamily(desc, config.ProviderConfig{ID: "z.ai"})
	if err != nil {
		t.Fatalf("buildFamily: %v", err)
	}
	if fam.Protocol() != contracts.WireOpenAI {
		t.Fatalf("protocol = %q", fam.Protocol())
	}
}

// TestBuildCloudCodeFamily proves the cloudcode branch builds a CloudCode family
// whose protocol is cloudcode.
func TestBuildCloudCodeFamily(t *testing.T) {
	desc := contracts.ProviderDescriptor{ID: "antigravity", Protocol: contracts.WireCloudCode}
	fam, err := buildFamily(desc, config.ProviderConfig{ID: "antigravity"})
	if err != nil {
		t.Fatalf("buildFamily: %v", err)
	}
	if fam.Protocol() != contracts.WireCloudCode {
		t.Fatalf("protocol = %q, want cloudcode", fam.Protocol())
	}
}

// TestCredentialsFilterUnsupportedMode proves a credential whose mode the family
// does not support is filtered out.
func TestCredentialsFilterUnsupportedMode(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")
	// z.ai supports APIKey only; store an OAuth credential for z.ai and confirm
	// it is filtered.
	sealed, err := a.Secrets.Seal([]byte("token-value-123456"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := a.Credentials.Upsert(context.Background(), contracts.Credential{
		ID: "z-oauth", Provider: "z.ai", AuthMode: contracts.AuthOAuth, Sealed: []byte(sealed),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	creds := credentialSource{store: a.Credentials, registry: a.Providers}
	got, err := creds.Credentials(context.Background(), "z.ai")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	for _, id := range got {
		if id == "z-oauth" {
			t.Fatal("an unsupported auth mode was not filtered")
		}
	}
}
