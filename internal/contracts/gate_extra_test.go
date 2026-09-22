package contracts

import (
	"testing"
)

// TestGateStageSet covers the bitmask helpers, including the empty set.
func TestGateStageSet(t *testing.T) {
	if got := StageSet().Has(StagePreRequest); got {
		t.Error("empty set reports a stage present")
	}
	set := StageSet(StagePreRequest, StageOnResponseChunk)
	if !set.Has(StagePreRequest) || !set.Has(StageOnResponseChunk) {
		t.Error("set missing a declared stage")
	}
	if set.Has(StagePostResponse) {
		t.Error("set reports an undeclared stage")
	}
	if set.Empty() {
		t.Error("non-empty set reports Empty")
	}
	if !StageSet().Empty() {
		t.Error("empty set reports non-empty")
	}
}

// TestFailurePolicyString covers both values (String had 0% coverage).
func TestFailurePolicyString(t *testing.T) {
	if got := FailClosed.String(); got != "fail_closed" {
		t.Errorf("FailClosed.String() = %q", got)
	}
	if got := FailOpen.String(); got != "fail_open" {
		t.Errorf("FailOpen.String() = %q", got)
	}
	// An out-of-range value renders as fail_closed: the String method's only
	// branch is FailOpen==1, so every other value (including 0/FailClosed)
	// reports fail_closed. Asserting it pins the safe default.
	if got := FailurePolicy(99).String(); got != "fail_closed" {
		t.Errorf("out-of-range FailurePolicy.String() = %q, want fail_closed", got)
	}
}

// TestGateRegistryFactories exercises Factories in deterministic order, which no
// existing test covered.
func TestGateRegistryFactories(t *testing.T) {
	r := NewGateRegistry()
	if len(r.Factories()) != 0 {
		t.Fatal("empty registry returned factories")
	}
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if err := r.RegisterGate(name, func() Gate {
			return stubGate{id: name, stages: StageSet(StagePreRequest)}
		}); err != nil {
			t.Fatalf("RegisterGate(%q): %v", name, err)
		}
	}

	factories := r.Factories()
	if len(factories) != 3 {
		t.Fatalf("Factories() len = %d, want 3", len(factories))
	}
	want := []string{"alpha", "mid", "zeta"}
	for i, f := range factories {
		if got := f().ID(); got != want[i] {
			t.Errorf("Factories()[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// TestGateInputFieldsArePlainValues is a light guard that the frozen input
// struct stays usable without any helper.
func TestGateInputFieldsArePlainValues(t *testing.T) {
	in := GateInput{Committed: false, Meta: map[string]string{"g.k": "v"}}
	if in.Committed {
		t.Error("Committed should be false")
	}
	if in.Meta["g.k"] != "v" {
		t.Error("Meta not carried")
	}
	chunk := ChunkInput{Committed: true, Index: 3}
	if !chunk.Committed || chunk.Index != 3 {
		t.Error("ChunkInput fields wrong")
	}
}

// TestDecisionVocabulary pins the enum values the pipeline switches on.
func TestDecisionVocabulary(t *testing.T) {
	kinds := []DecisionKind{DecisionContinue, DecisionModify, DecisionBlock, DecisionReroute}
	for i, k := range kinds {
		if int(k) != i {
			t.Errorf("DecisionKind %d = %d, want %d", i, k, i)
		}
	}
	chunks := []ChunkDecisionKind{ChunkPassThrough, ChunkReplace, ChunkDrop}
	for i, k := range chunks {
		if int(k) != i {
			t.Errorf("ChunkDecisionKind %d = %d, want %d", i, k, i)
		}
	}
	stages := []GateStage{StagePreRequest, StageOnResponseChunk, StagePostResponse}
	for i, s := range stages {
		if int(s) != i {
			t.Errorf("GateStage %d = %d, want %d", i, s, i)
		}
	}
}

// TestSentinelErrNotFound pins the sentinel's code so callers can rely on it.
func TestSentinelErrNotFound(t *testing.T) {
	if ErrNotFound == nil {
		t.Fatal("ErrNotFound is nil")
	}
	if ErrNotFound.Code != "error.not_found" {
		t.Errorf("ErrNotFound.Code = %q", ErrNotFound.Code)
	}
	if ErrNotFound.HTTPStatus != 404 {
		t.Errorf("ErrNotFound.HTTPStatus = %d, want 404", ErrNotFound.HTTPStatus)
	}
}
