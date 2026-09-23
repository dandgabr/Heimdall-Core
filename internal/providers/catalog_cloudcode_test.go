package providers

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// stubModelFamily is a family that implements the optional modelLister and
// modalizer extensions, so the Catalog's type assertions have a positive branch.
type stubModelFamily struct {
	id     domain.ProviderID
	models []domain.ModelID
	caps   contracts.Capabilities
	mods   contracts.ModalitySet
}

func (f stubModelFamily) ID() domain.ProviderID { return f.id }
func (f stubModelFamily) AuthModes() []contracts.AuthMode {
	return []contracts.AuthMode{contracts.AuthNone}
}
func (f stubModelFamily) Protocol() contracts.WireFormat { return contracts.WireOpenAI }
func (f stubModelFamily) Capabilities(m domain.ModelID) (contracts.Capabilities, bool) {
	for _, x := range f.models {
		if x == m {
			return f.caps, true
		}
	}
	return 0, false
}
func (f stubModelFamily) BuildExecutor(contracts.Credential, contracts.ExecutorDeps) (contracts.Executor, error) {
	return nil, nil
}
func (f stubModelFamily) Models() []domain.ModelID { return f.models }
func (f stubModelFamily) Modalities(m domain.ModelID) (contracts.ModalitySet, bool) {
	for _, x := range f.models {
		if x == m {
			return f.mods, true
		}
	}
	return 0, false
}

// plainFamily implements ONLY the frozen contract (no modelLister/modalizer), so
// the Catalog's "not a lister" branches are covered.
type plainFamily struct{ id domain.ProviderID }

func (f plainFamily) ID() domain.ProviderID           { return f.id }
func (f plainFamily) AuthModes() []contracts.AuthMode { return nil }
func (f plainFamily) Protocol() contracts.WireFormat  { return contracts.WireOpenAI }
func (f plainFamily) Capabilities(domain.ModelID) (contracts.Capabilities, bool) {
	return 0, false
}
func (f plainFamily) BuildExecutor(contracts.Credential, contracts.ExecutorDeps) (contracts.Executor, error) {
	return nil, nil
}

func TestCatalogOverRegistry(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(stubModelFamily{
		id: "a", models: []domain.ModelID{"m1", "m2"},
		caps: contracts.CapStream, mods: contracts.ModalitySet(0).Add(contracts.ModalityText),
	})
	_ = reg.Register(plainFamily{id: "b"})

	cat := NewCatalog(reg)
	if got := cat.Providers(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Providers = %v", got)
	}
	if got := cat.Models("a"); len(got) != 2 {
		t.Fatalf("Models(a) = %v", got)
	}
	// A family without a lister returns nil.
	if got := cat.Models("b"); got != nil {
		t.Fatalf("Models(b) = %v, want nil", got)
	}
	// Unknown provider.
	if got := cat.Models("ghost"); got != nil {
		t.Fatalf("Models(ghost) = %v, want nil", got)
	}
	if _, ok := cat.Capabilities("a", "m1"); !ok {
		t.Fatal("Capabilities(a,m1) not ok")
	}
	if _, ok := cat.Capabilities("ghost", "m1"); ok {
		t.Fatal("Capabilities(ghost) reported ok")
	}
	if _, ok := cat.Modalities("a", "m1"); !ok {
		t.Fatal("Modalities(a,m1) not ok")
	}
	// A family without a modalizer.
	if _, ok := cat.Modalities("b", "m1"); ok {
		t.Fatal("Modalities(b) reported ok without a modalizer")
	}
	if _, ok := cat.Modalities("ghost", "m1"); ok {
		t.Fatal("Modalities(ghost) reported ok")
	}
}

// TestCloudCodeFamilySurfaces covers the CloudCode family accessors.
func TestCloudCodeFamilySurfaces(t *testing.T) {
	desc := contracts.ProviderDescriptor{ID: "antigravity", Protocol: contracts.WireCloudCode}
	models := map[domain.ModelID]ModelCapabilities{
		"gemini-3.5-flash": {Capabilities: contracts.CapStream, Modalities: contracts.ModalitySet(0).Add(contracts.ModalityText)},
	}
	f, err := NewCloudCode(CloudCodeOptions{
		ID: "antigravity", Descriptor: desc, AuthModes: []contracts.AuthMode{contracts.AuthOAuth},
		Models: models, BaseURL: "https://example.invalid",
	})
	if err != nil {
		t.Fatalf("NewCloudCode: %v", err)
	}
	if f.ID() != "antigravity" || f.Protocol() != contracts.WireCloudCode {
		t.Fatalf("identity = %s / %s", f.ID(), f.Protocol())
	}
	if len(f.AuthModes()) != 1 || f.AuthModes()[0] != contracts.AuthOAuth {
		t.Fatalf("auth modes = %v", f.AuthModes())
	}
	if f.Descriptor().ID != "antigravity" {
		t.Fatalf("descriptor = %+v", f.Descriptor())
	}
	if got := f.Models(); len(got) != 1 || got[0] != "gemini-3.5-flash" {
		t.Fatalf("models = %v", got)
	}
	if _, ok := f.Capabilities("gemini-3.5-flash"); !ok {
		t.Fatal("Capabilities not ok")
	}
	if _, ok := f.Capabilities("nope"); ok {
		t.Fatal("Capabilities(nope) reported ok")
	}
	if _, ok := f.Modalities("gemini-3.5-flash"); !ok {
		t.Fatal("Modalities not ok")
	}
	if _, ok := f.Modalities("nope"); ok {
		t.Fatal("Modalities(nope) reported ok")
	}
}

// TestCloudCodeBuildExecutorBranches covers the credential-mismatch, auth-mode
// and success paths. The success path uses a stub executor deps bundle.
func TestCloudCodeBuildExecutorBranches(t *testing.T) {
	desc := contracts.ProviderDescriptor{ID: "antigravity", Protocol: contracts.WireCloudCode}
	f, _ := NewCloudCode(CloudCodeOptions{
		ID: "antigravity", Descriptor: desc, AuthModes: []contracts.AuthMode{contracts.AuthOAuth},
		Models: map[domain.ModelID]ModelCapabilities{}, BaseURL: "https://example.invalid",
	})

	// Credential from another family.
	_, err := f.BuildExecutor(contracts.Credential{Provider: "other", AuthMode: contracts.AuthOAuth}, stubDeps(t))
	if !hasCode(err, domain.CodeProviderInvalid) {
		t.Fatalf("mismatch err = %v", err)
	}
	// Unsupported auth mode.
	_, err = f.BuildExecutor(contracts.Credential{Provider: "antigravity", AuthMode: contracts.AuthAPIKey}, stubDeps(t))
	if !hasCode(err, domain.CodeProviderAuthModeUnsupported) {
		t.Fatalf("mode err = %v", err)
	}
	// Success: builds a CloudCode executor.
	exec, err := f.BuildExecutor(contracts.Credential{Provider: "antigravity", AuthMode: contracts.AuthOAuth}, stubDeps(t))
	if err != nil {
		t.Fatalf("BuildExecutor: %v", err)
	}
	if exec.Family() != "antigravity" {
		t.Fatalf("executor family = %s", exec.Family())
	}
}

// TestNewCloudCodeRejectsEmptyID covers the constructor guard.
func TestNewCloudCodeRejectsEmptyID(t *testing.T) {
	if _, err := NewCloudCode(CloudCodeOptions{}); err == nil {
		t.Fatal("NewCloudCode accepted an empty id")
	}
}

// TestNewCloudCodeDefaults covers the descriptor defaults (protocol, auth mode).
func TestNewCloudCodeDefaults(t *testing.T) {
	f, err := NewCloudCode(CloudCodeOptions{ID: "x"})
	if err != nil {
		t.Fatalf("NewCloudCode: %v", err)
	}
	if f.Protocol() != contracts.WireCloudCode {
		t.Fatalf("default protocol = %q", f.Protocol())
	}
	if len(f.AuthModes()) != 1 || f.AuthModes()[0] != contracts.AuthOAuth {
		t.Fatalf("default auth modes = %v", f.AuthModes())
	}
}

// stubDeps builds an ExecutorDeps bundle valid for CloudCode construction.
func stubDeps(t *testing.T) contracts.ExecutorDeps {
	t.Helper()
	return contracts.ExecutorDeps{
		Clock:    fakeClock{},
		IDs:      fakeIDs{},
		Redactor: fakeRedactor{},
		Egress:   fakeEgress{},
		Secrets:  stubOpener{},
	}
}

// stubOpener opens a sealed blob to a fixed plaintext.
type stubOpener struct{}

func (stubOpener) Open(string) ([]byte, error) { return []byte("token"), nil }
