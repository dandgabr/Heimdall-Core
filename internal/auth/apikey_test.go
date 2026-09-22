package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// testDeps is a deterministic, timeout-bounded dependency bundle for the flow
// factory tests.
func testDeps() oauth.ClientDeps {
	return oauth.ClientDeps{
		HTTP:  &http.Client{Timeout: 5 * time.Second},
		Clock: fixedClock{t: time.Now()},
	}
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestAPIKeyFlowKeyResult(t *testing.T) {
	f := NewAPIKeyFlow("z.ai", nil)

	res, err := f.KeyResult("sk-live-key", contracts.AccountMeta{Email: "u@example.com"})
	if err != nil {
		t.Fatalf("KeyResult: %v", err)
	}
	if res.AuthMode != contracts.AuthAPIKey {
		t.Errorf("auth mode = %v", res.AuthMode)
	}
	if res.Access.Reveal() != "sk-live-key" {
		t.Errorf("access = %q", res.Access.Reveal())
	}
	if !res.ExpiresAt.IsZero() {
		t.Errorf("a static key must have no expiry, got %v", res.ExpiresAt)
	}
	if res.Account.Email != "u@example.com" {
		t.Errorf("meta not carried: %+v", res.Account)
	}
}

func TestAPIKeyFlowRejectsEmptyKey(t *testing.T) {
	f := NewAPIKeyFlow("z.ai", nil)
	for _, key := range []string{"", "   ", "\t"} {
		if _, err := f.KeyResult(key, contracts.AccountMeta{}); err == nil {
			t.Errorf("empty key %q accepted", key)
		}
	}
}

// TestAPIKeyFlowValidatesFormat is the P0-C offline half: a key that is
// obviously not a key is rejected before it can be sealed, and a plausible key
// passes.
func TestAPIKeyFlowValidatesFormat(t *testing.T) {
	f := NewAPIKeyFlow("z.ai", nil)

	bad := map[string]string{
		"short":         "abc",
		"whitespace":    "sk-live key with spaces",
		"newline":       "sk-live\nkey",
		"control char":  "sk-live\x01key",
		"absurdly long": strings.Repeat("k", 5000),
	}
	for name, key := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := f.KeyResult(key, contracts.AccountMeta{}); err == nil {
				t.Fatalf("malformed key %q accepted", key)
			} else {
				assertCode(t, err, domain.CodeAuthKeyInvalidFormat)
			}
		})
	}

	if _, err := f.KeyResult("sk-live-0123456789abcdef", contracts.AccountMeta{}); err != nil {
		t.Fatalf("plausible key rejected: %v", err)
	}
}

// TestAPIKeyNetworkValidationHonest documents that network validation is not
// implemented for the API-key providers, so a caller cannot assume it happened.
func TestAPIKeyNetworkValidationHonest(t *testing.T) {
	f := NewAPIKeyFlow("z.ai", nil)
	implemented, err := f.ValidateNetwork(context.Background())
	if implemented {
		t.Fatal("ValidateNetwork claims implementation without a confirmed endpoint")
	}
	assertCode(t, err, domain.CodeAuthProviderPending)
}

func TestAPIKeyFlowIsOfflineForInteractiveOps(t *testing.T) {
	f := NewAPIKeyFlow("z.ai", nil)

	if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{}); err == nil {
		t.Error("Begin succeeded for a static key")
	} else {
		assertCode(t, err, domain.CodeAuthFlowNotInteractive)
	}
	if _, err := f.Poll(context.Background(), contracts.AuthChallenge{}); err == nil {
		t.Error("Poll succeeded for a static key")
	}
	if _, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{}); err == nil {
		t.Error("Refresh succeeded for a static key")
	}
	if f.Kind() != contracts.AuthAPIKey {
		t.Errorf("Kind = %v", f.Kind())
	}
}

func TestDescriptorsCoverFourProviders(t *testing.T) {
	descs := Descriptors()
	for _, id := range []domain.ProviderID{
		ProviderAntigravity, ProviderZAI, ProviderOllamaCloud, ProviderCommandCode,
	} {
		if _, ok := descs[id]; !ok {
			t.Errorf("descriptor missing for %s", id)
		}
	}

	// As of Wave 2 every endpoint is confirmed (ADR-0003): no provider is
	// pending, so the composition root may enable all four against the live
	// service.
	pending := PendingEndpoints()
	if len(pending) != 0 {
		t.Errorf("PendingEndpoints must be empty after Wave 2, got %v", pending)
	}

	// Antigravity is the confirmed OAuth provider: it must declare the full
	// CloudCode descriptor, client secret and obfuscation.
	ag := descs[ProviderAntigravity]
	if ag.Protocol != contracts.WireCloudCode {
		t.Errorf("antigravity protocol = %q, want %q", ag.Protocol, contracts.WireCloudCode)
	}
	if !ag.RequiresClientSecret || ag.ClientSecret == "" || ag.ClientID == "" {
		t.Errorf("antigravity client not configured: %+v", ag)
	}
	if !ag.IsObfuscated() || ag.RiskNotice == "" {
		t.Errorf("antigravity must declare obfuscation + a risk notice: %+v", ag)
	}
}

func TestDescriptorLookup(t *testing.T) {
	desc, err := Descriptor(ProviderZAI)
	if err != nil {
		t.Fatalf("Descriptor: %v", err)
	}
	if desc.Protocol != contracts.WireOpenAI {
		t.Errorf("z.ai protocol = %q", desc.Protocol)
	}
	if _, err := Descriptor("nope"); err == nil {
		t.Error("unknown provider accepted")
	} else {
		assertCode(t, err, domain.CodeProviderNotFound)
	}
}

// TestFlowFactoryBuildsAntigravityFlow is the Wave-2 replacement for the old
// "pending" guard: Antigravity's endpoints are confirmed, so Build must return
// the confidential-client AntigravityFlow (not refuse).
func TestFlowFactoryBuildsAntigravityFlow(t *testing.T) {
	f := NewFlowFactory(testDeps())
	flow, err := f.Build(ProviderAntigravity)
	if err != nil {
		t.Fatalf("Build(antigravity): %v", err)
	}
	if _, ok := flow.(*oauth.AntigravityFlow); !ok {
		t.Fatalf("Build(antigravity) = %T, want *oauth.AntigravityFlow", flow)
	}
}

// TestFlowFactoryRefusalIsDataDriven proves the pending refusal still works when
// a provider IS pending: a temporarily re-flagged descriptor fails closed.
func TestFlowFactoryRefusalIsDataDriven(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.pending = map[domain.ProviderID][]string{ProviderZAI: {"TokenEndpoint"}}
	f.modes[ProviderZAI] = []contracts.AuthMode{contracts.AuthOAuth}
	_, err := f.Build(ProviderZAI)
	assertCode(t, err, domain.CodeAuthProviderPending)
}

// TestFlowFactoryBuildsOAuthWhenEndpointsConfirmed proves the refusal is data-
// driven: once the pending list is empty for a provider, the OAuth flow builds.
func TestFlowFactoryBuildsOAuthWhenEndpointsConfirmed(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.modes[ProviderZAI] = []contracts.AuthMode{contracts.AuthOAuth}
	f.descriptors[ProviderZAI] = contracts.ProviderDescriptor{
		ID:            ProviderZAI,
		AuthEndpoint:  "https://example.test/auth",
		TokenEndpoint: "https://example.test/token",
	}
	flow, err := f.Build(ProviderZAI)
	if err != nil {
		t.Fatalf("Build(z.ai with endpoints): %v", err)
	}
	if flow.Kind() != contracts.AuthOAuth {
		t.Errorf("kind = %v, want oauth", flow.Kind())
	}
}

func TestFlowFactoryAPIKeyProviders(t *testing.T) {
	f := NewFlowFactory(testDeps())
	for _, id := range []domain.ProviderID{ProviderZAI, ProviderOllamaCloud, ProviderCommandCode} {
		flow, err := f.Build(id)
		if err != nil {
			t.Fatalf("Build(%s): %v", id, err)
		}
		if flow.Kind() != contracts.AuthAPIKey {
			t.Errorf("%s kind = %v, want api_key", id, flow.Kind())
		}
	}
	if _, err := f.Build("nope"); err == nil {
		t.Error("unknown provider built a flow")
	}
}

func TestFlowFactoryProvidersDeterministic(t *testing.T) {
	f := NewFlowFactory(testDeps())
	got := f.Providers()
	want := []domain.ProviderID{"antigravity", "command-code", "ollama-cloud", "z.ai"}
	if len(got) != len(want) {
		t.Fatalf("Providers() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Providers() = %v, want %v", got, want)
		}
	}
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != want {
		t.Fatalf("err = %v, want code %s", err, want)
	}
}
