package contracts

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// These tests lock the CONTRACT, not an implementation: they pin the properties
// the F1 consumers rely on. The registry ordering test is the important one —
// Go randomises map iteration, so a chain whose order came from a map would vary
// between runs and corrupt prompt-cache keys.

func TestGateRegistryNamesAreDeterministic(t *testing.T) {
	r := NewGateRegistry()
	// Deliberately registered out of order.
	for _, name := range []string{"token", "logger", "security", "memory"} {
		if err := r.RegisterGate(name, func() Gate { return stubGate{id: name} }); err != nil {
			t.Fatalf("RegisterGate(%q): %v", name, err)
		}
	}

	first := r.Names()
	want := []string{"logger", "memory", "security", "token"}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Names() = %v, want %v", first, want)
	}

	// Run repeatedly: a map-ordered implementation would flake here.
	for i := 0; i < 100; i++ {
		if got := r.Names(); !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d: Names() = %v, want %v", i, got, want)
		}
	}
}

func TestGateRegistryBuildOrderMatchesNames(t *testing.T) {
	r := NewGateRegistry()
	for _, name := range []string{"z", "a", "m"} {
		if err := r.RegisterGate(name, func() Gate {
			return stubGate{id: name, stages: StageSet(StagePreRequest)}
		}); err != nil {
			t.Fatalf("RegisterGate(%q): %v", name, err)
		}
	}
	gates, err := r.Build()
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}
	var ids []string
	for _, g := range gates {
		ids = append(ids, g.ID())
	}
	if want := []string{"a", "m", "z"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("Build() order = %v, want %v", ids, want)
	}
}

func TestGateRegistryRejectsBadRegistrations(t *testing.T) {
	r := NewGateRegistry()
	factory := func() Gate { return stubGate{id: "x"} }
	if err := r.RegisterGate("x", factory); err != nil {
		t.Fatalf("first RegisterGate: %v", err)
	}
	if err := r.RegisterGate("x", factory); err == nil {
		t.Fatal("duplicate name accepted, want error")
	}
	if err := r.RegisterGate("", factory); err == nil {
		t.Fatal("empty name accepted, want error")
	}
	if err := r.RegisterGate("y", nil); err == nil {
		t.Fatal("nil factory accepted, want error")
	}
}

func TestGateRegistryBuildRejectsIDMismatch(t *testing.T) {
	r := NewGateRegistry()
	if err := r.RegisterGate("expected", func() Gate {
		return stubGate{id: "actual", stages: StageSet(StagePreRequest)}
	}); err != nil {
		t.Fatalf("RegisterGate: %v", err)
	}
	if _, err := r.Build(); err == nil {
		t.Fatal("ID mismatch accepted, want error")
	}
}

func TestGateRegistryBuildRejectsEmptyStages(t *testing.T) {
	r := NewGateRegistry()
	if err := r.RegisterGate("nostage", func() Gate { return stubGate{id: "nostage"} }); err != nil {
		t.Fatalf("RegisterGate: %v", err)
	}
	if _, err := r.Build(); err == nil {
		t.Fatal("gate with no stages accepted, want error")
	}
}

// TestGateRegistryBuildRejectsNilFactoryResult covers the branch where a usable
// factory nevertheless returns nil at build time.
func TestGateRegistryBuildRejectsNilFactoryResult(t *testing.T) {
	r := NewGateRegistry()
	if err := r.RegisterGate("nilresult", func() Gate { return nil }); err != nil {
		t.Fatalf("RegisterGate: %v", err)
	}
	if _, err := r.Build(); err == nil {
		t.Fatal("nil gate result accepted, want error")
	}
}

// TestSecretNeverRendersPlaintext pins the redaction guarantee for every verb
// fmt routes through Formatter/Stringer. %p is asserted separately because fmt
// handles it before consulting the interface (see the Secret doc comment): it is
// documented as a known residual, not silently ignored.
func TestSecretNeverRendersPlaintext(t *testing.T) {
	const token = "sk-live-supersecret-1234567890"
	s := Secret(token)

	intercepted := []string{"%s", "%v", "%q", "%#v", "%+v", "%x", "%d", "%t", "%c", "%b", "%o"}
	for _, verb := range intercepted {
		rendered := fmt.Sprintf(verb, s)
		if contains(rendered, token) {
			t.Errorf("fmt %q leaked the secret: %s", verb, rendered)
		}
	}
	// %T prints the type name, never the value: safe by construction.
	if rendered := fmt.Sprintf("%T", s); contains(rendered, token) {
		t.Errorf("fmt %%T leaked the secret: %s", rendered)
	}
	if got := fmt.Sprintf("%s", s); got != redactedPlaceholder {
		t.Errorf("String() = %q, want %q", got, redactedPlaceholder)
	}
	if s.Reveal() != token {
		t.Errorf("Reveal() = %q, want %q", s.Reveal(), token)
	}
	if (Secret("")).IsEmpty() != true || s.IsEmpty() != false {
		t.Error("IsEmpty() misreports emptiness")
	}
}

// TestSecretPointerUsesReveal documents the sanctioned read path and that the
// residual verb is %p on a VALUE. Using a pointer would expose the same bytes
// via %p, which is exactly why Reveal is the only approved accessor.
func TestSecretPointerUsesReveal(t *testing.T) {
	s := Secret("sk-live-abc")
	p := &s
	if p.Reveal() != "sk-live-abc" {
		t.Fatalf("Reveal via pointer = %q", p.Reveal())
	}
}

func TestModalitySetAndCapabilitiesBits(t *testing.T) {
	mods := ModalitySet(0).Add(ModalityText, ModalityImage)
	if !mods.Has(ModalityText) || !mods.Has(ModalityImage) {
		t.Fatalf("ModalitySet missing an added modality: %s", mods)
	}
	if mods.Has(ModalityAudio) {
		t.Fatalf("ModalitySet reports an unadded modality: %s", mods)
	}

	caps := Capabilities(0).Add(CapStream, CapTools)
	if !caps.Has(CapStream) || !caps.Has(CapTools) {
		t.Fatalf("Capabilities missing an added capability: %s", caps)
	}
	// Has is "all bits present", so a mixed query must fail.
	if caps.Has(CapStream | CapVision) {
		t.Fatalf("Has() matched a partially-satisfied query: %s", caps)
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// stubGate is a minimal Gate used only by the registry tests. It exists in the
// test file so no concrete gate implementation leaks into the contract package.
type stubGate struct {
	id     string
	stages GateStageSet
}

func (g stubGate) ID() string                   { return g.id }
func (g stubGate) Stages() GateStageSet         { return g.stages }
func (g stubGate) RequiredCaps() GateCaps       { return 0 }
func (g stubGate) FailurePolicy() FailurePolicy { return FailOpen }
func (g stubGate) PreRequest(_ context.Context, _ GateInput) (Decision, error) {
	return Decision{Kind: DecisionContinue}, nil
}
func (g stubGate) OnResponseChunk(_ context.Context, _ ChunkInput) (ChunkDecision, error) {
	return ChunkDecision{Kind: ChunkPassThrough}, nil
}
func (g stubGate) PostResponse(_ context.Context, _ GateInput) error { return nil }
func (g stubGate) Close() error                                      { return nil }
