package auth

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func TestAuthModesFor(t *testing.T) {
	if got := AuthModesFor(ProviderAntigravity); len(got) != 1 || got[0] != contracts.AuthOAuth {
		t.Errorf("AuthModesFor(antigravity) = %v, want [oauth]", got)
	}
	for _, id := range []domain.ProviderID{ProviderZAI, ProviderOllamaCloud, ProviderCommandCode} {
		if got := AuthModesFor(id); len(got) != 1 || got[0] != contracts.AuthAPIKey {
			t.Errorf("AuthModesFor(%s) = %v, want [api_key]", id, got)
		}
	}
	if got := AuthModesFor("unknown"); got != nil {
		t.Errorf("AuthModesFor(unknown) = %v, want nil", got)
	}
}

func TestFlowFactoryAuthModes(t *testing.T) {
	f := NewFlowFactory(testDeps())
	if got := f.AuthModes(ProviderAntigravity); len(got) != 1 || got[0] != contracts.AuthOAuth {
		t.Errorf("FlowFactory.AuthModes(antigravity) = %v", got)
	}
	if got := f.AuthModes(ProviderZAI); len(got) != 1 || got[0] != contracts.AuthAPIKey {
		t.Errorf("FlowFactory.AuthModes(z.ai) = %v", got)
	}
	if got := f.AuthModes("unknown"); got != nil {
		t.Errorf("FlowFactory.AuthModes(unknown) = %v, want nil", got)
	}
}

func TestPendingFields(t *testing.T) {
	// Wave 2: every endpoint is confirmed, so no provider reports pending
	// fields and the factory enables all four.
	if fields := PendingFields(ProviderAntigravity); len(fields) != 0 {
		t.Errorf("antigravity pending fields = %v, want none", fields)
	}
	if got := PendingFields(ProviderZAI); len(got) != 0 {
		t.Errorf("z.ai pending fields = %v, want none", got)
	}
}

// TestFlowFactoryBuildUnknownProvider covers Build's not-found branch.
func TestFlowFactoryBuildUnknownProvider(t *testing.T) {
	f := NewFlowFactory(testDeps())
	_, err := f.Build("does-not-exist")
	assertCode(t, err, domain.CodeProviderNotFound)
}

// TestFlowFactoryBuildNoMode covers the "provider has no auth mode" branch.
func TestFlowFactoryBuildNoMode(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.modes[ProviderZAI] = nil
	_, err := f.Build(ProviderZAI)
	assertCode(t, err, domain.CodeProviderInvalid)
}

// TestFlowFactoryBuildPKCEWhenNoDeviceEndpoint covers the AuthOAuth branch that
// selects PKCE when no device endpoint is present.
func TestFlowFactoryBuildPKCEWhenNoDeviceEndpoint(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.modes[ProviderZAI] = []contracts.AuthMode{contracts.AuthOAuth}
	f.descriptors[ProviderZAI] = contracts.ProviderDescriptor{
		ID:            ProviderZAI,
		AuthEndpoint:  "https://example.test/auth",
		TokenEndpoint: "https://example.test/token",
		// No DeviceAuthEndpoint -> PKCE.
	}
	flow, err := f.Build(ProviderZAI)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if flow.Kind() != contracts.AuthOAuth {
		t.Errorf("kind = %v, want oauth", flow.Kind())
	}
}

// TestFlowFactoryBuildUnsupportedMode covers the default branch: a mode that is
// neither OAuth nor APIKey (AuthNone) has no flow.
func TestFlowFactoryBuildUnsupportedMode(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.modes[ProviderZAI] = []contracts.AuthMode{contracts.AuthNone}
	_, err := f.Build(ProviderZAI)
	assertCode(t, err, domain.CodeProviderInvalid)
}

// TestFlowFactoryPrefersOAuthAmongModes covers the preference loop: when a
// provider lists both APIKey and OAuth, OAuth wins regardless of order.
func TestFlowFactoryPrefersOAuthAmongModes(t *testing.T) {
	f := NewFlowFactory(testDeps())
	f.modes[ProviderZAI] = []contracts.AuthMode{contracts.AuthAPIKey, contracts.AuthOAuth}
	f.descriptors[ProviderZAI] = contracts.ProviderDescriptor{
		ID:                 ProviderZAI,
		DeviceAuthEndpoint: "https://example.test/device",
		TokenEndpoint:      "https://example.test/token",
	}
	flow, err := f.Build(ProviderZAI)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if flow.Kind() != contracts.AuthOAuth {
		t.Errorf("kind = %v, want oauth (OAuth must be preferred)", flow.Kind())
	}
}
