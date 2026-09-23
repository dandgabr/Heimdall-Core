package providers

import (
	"net/http"
	"testing"
	"time"

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

// TestRegistryAllowlistQuery covers the Has/DeclaresModel methods that satisfy
// combos.ProviderSet (the combo allowlist, ADR-0013 §3.6).
func TestRegistryAllowlistQuery(t *testing.T) {
	r := NewRegistry()
	f, err := NewOpenAICompat(OpenAICompatOptions{
		ID: "z.ai",
		Models: map[domain.ModelID]ModelCapabilities{
			"glm-5": {Capabilities: contracts.Capabilities(0).Add(contracts.CapStream)},
		},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	if err := r.Register(f); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if !r.Has("z.ai") {
		t.Error("Has(z.ai) = false")
	}
	if r.Has("ghost") {
		t.Error("Has(ghost) = true")
	}
	if !r.DeclaresModel("glm-5") {
		t.Error("DeclaresModel(glm-5) = false")
	}
	if r.DeclaresModel("ghost") {
		t.Error("DeclaresModel(ghost) = true")
	}
}

// TestDeclaresModelSkipsNil covers the nil-family guard in DeclaresModel.
func TestDeclaresModelSkipsNil(t *testing.T) {
	r := NewRegistry()
	// Inject a nil family directly (Register rejects nil, but the guard must
	// still hold if the map is ever populated another way).
	r.families["nil"] = nil
	if r.DeclaresModel("glm-5") {
		t.Error("DeclaresModel with a nil family = true")
	}
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

// TestOpenAICompatDescriptorAndIDs covers the Descriptor accessor and the
// registry IDs accessor (both 0% before).
func TestOpenAICompatDescriptorAndIDs(t *testing.T) {
	f, err := NewOpenAICompat(OpenAICompatOptions{
		ID: "z.ai",
		Descriptor: contracts.ProviderDescriptor{
			DisplayName: "Z.ai",
		},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	desc := f.Descriptor()
	if desc.ID != "z.ai" || desc.Protocol != contracts.WireOpenAI || desc.DisplayName != "Z.ai" {
		t.Errorf("Descriptor = %+v", desc)
	}

	r := NewRegistry()
	if err := r.Register(f); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.Register(stubFamily("antigravity")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ids := r.IDs()
	if len(ids) != 2 || ids[0] != "antigravity" || ids[1] != "z.ai" {
		t.Errorf("IDs() = %v, want [antigravity z.ai]", ids)
	}
}

// TestOpenAICompatModalitiesUnknown covers the Modalities miss branch.
func TestOpenAICompatModalitiesUnknown(t *testing.T) {
	f, _ := NewOpenAICompat(OpenAICompatOptions{
		ID: "z.ai",
		Models: map[domain.ModelID]ModelCapabilities{
			"known": {Modalities: contracts.ModalitySet(0).Add(contracts.ModalityText)},
		},
	})
	if _, ok := f.Modalities("unknown"); ok {
		t.Error("unknown model reported Modalities ok=true")
	}
	if mods, ok := f.Modalities("known"); !ok || !mods.Has(contracts.ModalityText) {
		t.Errorf("known model = %v, %v", mods, ok)
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

// TestBuildExecutorWiring pins the F2.2 BuildExecutor decisions: it refuses a
// credential from another family and a family with no BaseURL, and it builds a
// real executor (satisfying the full frozen contract) when wired correctly.
func TestBuildExecutorWiring(t *testing.T) {
	f, _ := NewOpenAICompat(OpenAICompatOptions{
		ID:      "z.ai",
		BaseURL: "https://api.example.com/v1",
	})
	deps := contracts.ExecutorDeps{
		Clock: fakeClock{}, IDs: fakeIDs{}, Redactor: fakeRedactor{}, Egress: fakeEgress{},
	}

	exec, err := f.BuildExecutor(contracts.Credential{
		ID: "c1", Provider: "z.ai", AuthMode: contracts.AuthAPIKey,
	}, deps)
	if err != nil {
		t.Fatalf("BuildExecutor: %v", err)
	}
	if exec.Family() != "z.ai" {
		t.Errorf("executor family = %q", exec.Family())
	}

	// A credential from another family is refused.
	if _, err := f.BuildExecutor(contracts.Credential{Provider: "other"}, deps); err == nil {
		t.Error("executor built for a credential of another family")
	}

	// A family without a BaseURL cannot build an executor.
	noURL, _ := NewOpenAICompat(OpenAICompatOptions{ID: "nourl"})
	if _, err := noURL.BuildExecutor(contracts.Credential{Provider: "nourl", AuthMode: contracts.AuthAPIKey}, deps); !hasCode(err, domain.CodeProviderInvalid) {
		t.Errorf("no-URL BuildExecutor err = %v, want %s", err, domain.CodeProviderInvalid)
	}

	// An auth mode the family does not declare is refused.
	if _, err := f.BuildExecutor(contracts.Credential{Provider: "z.ai", AuthMode: contracts.AuthOAuth}, deps); !hasCode(err, domain.CodeProviderAuthModeUnsupported) {
		t.Errorf("OAuth BuildExecutor err = %v, want %s", err, domain.CodeProviderAuthModeUnsupported)
	}
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Now() }

type fakeIDs struct{}

func (fakeIDs) NewRequestID() domain.RequestID { return "r" }

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

type fakeEgress struct{}

func (fakeEgress) Client(contracts.EgressSpec) (contracts.HTTPDoer, error) { return fakeDoer{}, nil }

type fakeDoer struct{}

func (fakeDoer) Do(*http.Request) (*http.Response, error) { return nil, nil }

// hasCode reports whether err is a DomainError with the given code.
func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
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
