package translators

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func TestRegistryRegisterLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(AnthropicToOpenAI{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := r.Lookup(contracts.WireOpenAI, contracts.WireAnthropic)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, ok := got.(AnthropicToOpenAI); !ok {
		t.Fatalf("Lookup returned %T", got)
	}
}

func TestRegistryLookupMissing(t *testing.T) {
	r := NewRegistry()
	_, err := r.Lookup(contracts.WireAnthropic, contracts.WireGemini)
	assertCode(t, err, domain.CodeTranslateUnsupported)
	de, _ := err.(*domain.DomainError)
	if de.Params["from"] != "anthropic" || de.Params["to"] != "gemini" {
		t.Errorf("params = %v", de.Params)
	}
}

func TestRegistryRejectsDuplicatesNilAndEmpty(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(AnthropicToOpenAI{}); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Duplicate pair.
	assertCode(t, r.Register(AnthropicToOpenAI{}), domain.CodeTranslateFailed)
	// Nil translator.
	assertCode(t, r.Register(nil), domain.CodeTranslateUnsupported)
	// Empty formats.
	assertCode(t, r.Register(emptyFormatTranslator{}), domain.CodeTranslateUnsupported)
}

func TestRegistryPairsAreDeterministic(t *testing.T) {
	r := NewRegistry()
	// Register out of order.
	for _, tr := range []contracts.Translator{GeminiToOpenAI{}, Identity{}, AnthropicToOpenAI{}} {
		if err := r.Register(tr); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	want := [][2]contracts.WireFormat{
		{contracts.WireOpenAI, contracts.WireAnthropic},
		{contracts.WireOpenAI, contracts.WireGemini},
		{contracts.WireOpenAI, contracts.WireOpenAI},
	}
	for i := 0; i < 100; i++ {
		got := r.Pairs()
		if len(got) != len(want) {
			t.Fatalf("Pairs len = %d, want %d", len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: Pairs[%d] = %v, want %v", i, j, got[j], want[j])
			}
		}
	}
}

func TestRegistryFormatsDeterministic(t *testing.T) {
	r := NewRegistry()
	for _, tr := range []contracts.Translator{GeminiToOpenAI{}, Identity{}, AnthropicToOpenAI{}} {
		if err := r.Register(tr); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	got := r.Formats()
	if len(got) != 1 || got[0] != contracts.WireOpenAI {
		t.Fatalf("Formats = %v, want [openai]", got)
	}
}

func TestDefaultRegistry(t *testing.T) {
	r, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	for _, want := range [][2]contracts.WireFormat{
		{contracts.WireOpenAI, contracts.WireOpenAI},
		{contracts.WireOpenAI, contracts.WireAnthropic},
		{contracts.WireOpenAI, contracts.WireGemini},
	} {
		if _, err := r.Lookup(want[0], want[1]); err != nil {
			t.Errorf("Default missing pair %v: %v", want, err)
		}
	}
}

// TestDefaultRegistryDuplicateFails covers buildDefault's error branch by
// passing a list that contains the same pair twice.
func TestBuildDefaultDuplicateFails(t *testing.T) {
	_, err := buildDefault([]contracts.Translator{Identity{}, Identity{}})
	assertCode(t, err, domain.CodeTranslateFailed)
}

// TestBuildDefaultEmpty covers the zero-iteration path.
func TestBuildDefaultEmpty(t *testing.T) {
	r, err := buildDefault(nil)
	if err != nil {
		t.Fatalf("buildDefault(nil): %v", err)
	}
	if len(r.Pairs()) != 0 {
		t.Errorf("pairs = %v, want empty", r.Pairs())
	}
}
func TestDefaultRegistryIsFresh(t *testing.T) {
	a, err := Default()
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := Default()
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatal("Default returned a shared registry")
	}
}

// TestRegistryRegisterTwiceForSamePairAcrossSeparateRegistries is a guard that
// the duplicate check is per-registry, not global.
func TestRegistryDuplicateIsPerRegistry(t *testing.T) {
	a, b := NewRegistry(), NewRegistry()
	if err := a.Register(Identity{}); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := b.Register(Identity{}); err != nil {
		t.Fatalf("b: %v", err)
	}
}

// emptyFormatTranslator reports empty formats so Register's guard is reachable.
type emptyFormatTranslator struct{}

func (emptyFormatTranslator) From() contracts.WireFormat { return "" }
func (emptyFormatTranslator) To() contracts.WireFormat   { return "" }
func (emptyFormatTranslator) Request(b []byte, _ string, _ bool) ([]byte, error) {
	return b, nil
}
func (emptyFormatTranslator) ResponseFull(b []byte, _ string) ([]byte, error) { return b, nil }
func (emptyFormatTranslator) ResponseChunk(b []byte, _ string) ([]byte, error) {
	return b, nil
}
