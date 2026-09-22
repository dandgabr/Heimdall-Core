package providers

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func stubFamily(id domain.ProviderID) contracts.ProviderFamily {
	f, err := NewOpenAICompat(OpenAICompatOptions{ID: id})
	if err != nil {
		panic(err)
	}
	return f
}

func TestRegistryRegisterGetAll(t *testing.T) {
	r := NewRegistry()
	// Register out of lexical order.
	for _, id := range []domain.ProviderID{"z.ai", "antigravity", "ollama-cloud"} {
		if err := r.Register(stubFamily(id)); err != nil {
			t.Fatalf("Register(%s): %v", id, err)
		}
	}

	got, err := r.Get("z.ai")
	if err != nil || got.ID() != "z.ai" {
		t.Fatalf("Get(z.ai) = %v, %v", got, err)
	}

	// All() must be deterministic (lexical), not map order.
	want := []domain.ProviderID{"antigravity", "ollama-cloud", "z.ai"}
	for i := 0; i < 100; i++ {
		all := r.All()
		if len(all) != len(want) {
			t.Fatalf("All() len = %d, want %d", len(all), len(want))
		}
		for j, f := range all {
			if f.ID() != want[j] {
				t.Fatalf("iteration %d: All()[%d] = %s, want %s", i, j, f.ID(), want[j])
			}
		}
	}
}

func TestRegistryRejectsDuplicatesNilAndEmpty(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubFamily("x")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	err := r.Register(stubFamily("x"))
	assertCode(t, err, domain.CodeProviderDuplicate)

	err = r.Register(nil)
	assertCode(t, err, domain.CodeProviderInvalid)

	// A family with an empty ID cannot be built through the constructor, so
	// exercise the registry guard with a hand-rolled empty family.
	err = r.Register(emptyFamily{})
	assertCode(t, err, domain.CodeProviderInvalid)
}

func TestRegistryGetMissing(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nope")
	assertCode(t, err, domain.CodeProviderNotFound)
}

func TestOpenAICompatCapabilities(t *testing.T) {
	f, err := NewOpenAICompat(OpenAICompatOptions{
		ID: "z.ai",
		Models: map[domain.ModelID]ModelCapabilities{
			"glm-5": {
				Capabilities: contracts.Capabilities(0).Add(contracts.CapStream, contracts.CapTools),
				Modalities:   contracts.ModalitySet(0).Add(contracts.ModalityText),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}

	caps, ok := f.Capabilities("glm-5")
	if !ok || !caps.Has(contracts.CapStream) || !caps.Has(contracts.CapTools) {
		t.Fatalf("Capabilities(glm-5) = %v, %v", caps, ok)
	}
	mods, ok := f.Modalities("glm-5")
	if !ok || !mods.Has(contracts.ModalityText) {
		t.Fatalf("Modalities(glm-5) = %v, %v", mods, ok)
	}

	// An unknown model must be ok=false, never an empty-with-ok=true set.
	if _, ok := f.Capabilities("unknown"); ok {
		t.Error("unknown model reported ok=true; the contract forbids it")
	}
}

func TestOpenAICompatDefaults(t *testing.T) {
	f, err := NewOpenAICompat(OpenAICompatOptions{ID: "cmd"})
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	if f.Protocol() != contracts.WireOpenAI {
		t.Errorf("protocol = %q, want openai", f.Protocol())
	}
	modes := f.AuthModes()
	if len(modes) != 1 || modes[0] != contracts.AuthAPIKey {
		t.Errorf("auth modes = %v, want [api_key]", modes)
	}
	if _, err := NewOpenAICompat(OpenAICompatOptions{}); err == nil {
		t.Error("empty ID accepted")
	}
}

// TestBuildExecutorIsAStub proves the F1 placeholder satisfies the frozen seam
// and rejects a credential from another family (a real guard, not a stub).
func TestBuildExecutorIsAStub(t *testing.T) {
	f, _ := NewOpenAICompat(OpenAICompatOptions{ID: "z.ai"})

	exec, err := f.BuildExecutor(contracts.Credential{
		ID:       "c1",
		Provider: "z.ai",
		AuthMode: contracts.AuthAPIKey,
	}, contracts.ExecutorDeps{})
	if err != nil {
		t.Fatalf("BuildExecutor: %v", err)
	}
	if exec.Family() != "z.ai" {
		t.Errorf("stub executor family = %q", exec.Family())
	}

	if _, err := f.BuildExecutor(contracts.Credential{Provider: "other"}, contracts.ExecutorDeps{}); err == nil {
		t.Error("executor built for a credential of another family")
	}
}

func TestOpenAICompatModelsDeterministic(t *testing.T) {
	f, _ := NewOpenAICompat(OpenAICompatOptions{
		ID: "m",
		Models: map[domain.ModelID]ModelCapabilities{
			"c": {}, "a": {}, "b": {},
		},
	})
	models := f.Models()
	want := []domain.ModelID{"a", "b", "c"}
	for i, m := range models {
		if m != want[i] {
			t.Fatalf("Models() = %v, want %v", models, want)
		}
	}
}

type emptyFamily struct{}

func (emptyFamily) ID() domain.ProviderID           { return "" }
func (emptyFamily) AuthModes() []contracts.AuthMode { return nil }
func (emptyFamily) Protocol() contracts.WireFormat  { return contracts.WireOpenAI }
func (emptyFamily) Capabilities(domain.ModelID) (contracts.Capabilities, bool) {
	return 0, false
}
func (emptyFamily) BuildExecutor(contracts.Credential, contracts.ExecutorDeps) (contracts.Executor, error) {
	return nil, nil
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", want)
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != want {
		t.Fatalf("err = %v, want code %s", err, want)
	}
}
