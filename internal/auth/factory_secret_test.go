package auth

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestNewFlowFactoryWithSecretsCopiesAndFilters proves the factory copies the
// injected map, drops empty values, and does not mutate the caller's map.
func TestNewFlowFactoryWithSecretsCopiesAndFilters(t *testing.T) {
	caller := map[domain.ProviderID]string{
		ProviderAntigravity: "secret-a",
		ProviderZAI:         "", // empty is dropped (not a usable secret)
	}
	f := NewFlowFactoryWithSecrets(testDeps(), caller)

	if f.secrets[ProviderAntigravity] != "secret-a" {
		t.Fatalf("antigravity secret not injected: %v", f.secrets)
	}
	if _, ok := f.secrets[ProviderZAI]; ok {
		t.Fatalf("an empty secret was stored: %v", f.secrets)
	}
	// Mutating the caller's map must not change the factory's copy.
	caller[ProviderAntigravity] = "changed"
	if f.secrets[ProviderAntigravity] != "secret-a" {
		t.Fatal("the factory did not copy the secrets map")
	}
}

// TestFlowFactorySecretsNilMapIsSafe proves a nil secrets map is accepted and
// Antigravity still fails closed rather than panicking.
func TestFlowFactorySecretsNilMapIsSafe(t *testing.T) {
	f := NewFlowFactoryWithSecrets(testDeps(), nil)
	_, err := f.Build(ProviderAntigravity)
	assertCode(t, err, domain.CodeAuthProviderClientSecretMissing)
}

// TestFlowFactoryInjectsSecretOntoCopy proves Build binds the secret onto a COPY
// of the descriptor, leaving the package-level descriptor secret-free (so a
// second Build sees the same state and the shared map is never mutated).
func TestFlowFactoryInjectsSecretOntoCopy(t *testing.T) {
	f := NewFlowFactoryWithSecrets(testDeps(), map[domain.ProviderID]string{
		ProviderAntigravity: "injected",
	})
	if _, err := f.Build(ProviderAntigravity); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := f.descriptors[ProviderAntigravity].ClientSecret; got != "" {
		t.Fatalf("the factory's descriptor map was mutated: %q", got)
	}
	if got := Descriptors()[ProviderAntigravity].ClientSecret; got != "" {
		t.Fatalf("the package descriptor map was mutated: %q", got)
	}
}
