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

	// Only Antigravity has pending endpoints; the API-key providers are complete.
	pending := PendingEndpoints()
	if _, ok := pending[ProviderAntigravity]; !ok {
		t.Error("Antigravity must be flagged as having unconfirmed endpoints")
	}
	if _, ok := pending[ProviderZAI]; ok {
		t.Error("z.ai must not be flagged: it needs no OAuth endpoints")
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

// TestFlowFactoryRefusesPendingAntigravity is the P0-C regression guard: while
// the provider's endpoints are placeholders, Build must refuse with an explicit
// code (auth.provider_pending_endpoints), never build a flow that can only fail
// against the live service and never crash.
func TestFlowFactoryRefusesPendingAntigravity(t *testing.T) {
	f := NewFlowFactory(testDeps())
	flow, err := f.Build(ProviderAntigravity)
	if err == nil {
		t.Fatalf("Build(antigravity) succeeded while endpoints are pending: %v", flow)
	}
	assertCode(t, err, domain.CodeAuthProviderPending)
	de := err.(*domain.DomainError)
	if de.Params["provider"] != "antigravity" {
		t.Errorf("error params missing provider: %+v", de.Params)
	}
	if de.Params["fields"] == "" {
		t.Error("error params must name the pending fields")
	}
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
