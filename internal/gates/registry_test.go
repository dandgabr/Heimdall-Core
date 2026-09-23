package gates

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// depGate is a test gate with a declared read/write set.
type depGate struct {
	id     string
	stages contracts.GateStageSet
	reads  []contracts.DataField
	writes []contracts.DataField
	after  []string
	policy contracts.FailurePolicy
}

func (g *depGate) ID() string                             { return g.id }
func (g *depGate) Stages() contracts.GateStageSet         { return g.stages }
func (g *depGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (g *depGate) FailurePolicy() contracts.FailurePolicy { return g.policy }
func (g *depGate) Declare() contracts.Declared {
	return contracts.Declared{Stages: g.stages, Reads: g.reads, Writes: g.writes, After: g.after}
}
func (g *depGate) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (g *depGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (g *depGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (g *depGate) Close() error                                            { return nil }

func preStages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// ids returns the gate IDs in order.
func ids(gs []contracts.Gate) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.ID()
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRegistryOrderByDependency proves the topological order follows the data
// dependency: a gate that WRITES prompt_text runs before a gate that READS it,
// regardless of registration order.
func TestRegistryOrderByDependency(t *testing.T) {
	r := NewRegistry()
	// Register the READER first, the WRITER second.
	mustRegister(t, r, &depGate{id: "reader", stages: preStages(), reads: []contracts.DataField{contracts.FieldPromptText}})
	mustRegister(t, r, &depGate{id: "writer", stages: preStages(), writes: []contracts.DataField{contracts.FieldPromptText}})

	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := ids(order.PreRequest)
	if !eq(got, []string{"writer", "reader"}) {
		t.Fatalf("order = %v, want [writer reader]", got)
	}
}

// TestRegistryTieBreakByName proves an unordered set is ordered lexicographically
// by ID (ADR-0014 §1.3), independent of registration order.
func TestRegistryTieBreakByName(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "zebra", stages: preStages()})
	mustRegister(t, r, &depGate{id: "alpha", stages: preStages()})
	mustRegister(t, r, &depGate{id: "mike", stages: preStages()})

	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := ids(order.PreRequest); !eq(got, []string{"alpha", "mike", "zebra"}) {
		t.Fatalf("order = %v, want alphabetical", got)
	}
}

// TestRegistryAfterExplicitEdge proves an explicit After dependency orders a
// gate even without a data edge.
func TestRegistryAfterExplicitEdge(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "a", stages: preStages()})
	mustRegister(t, r, &depGate{id: "b", stages: preStages(), after: []string{"a"}})

	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := ids(order.PreRequest); !eq(got, []string{"a", "b"}) {
		t.Fatalf("order = %v, want [a b]", got)
	}
}

// TestRegistryCycleRejected proves a data-dependency cycle is rejected at boot
// (ADR-0014 §1.4).
func TestRegistryCycleRejected(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "a", stages: preStages(), writes: []contracts.DataField{contracts.FieldPromptText}, reads: []contracts.DataField{contracts.FieldBudget}})
	mustRegister(t, r, &depGate{id: "b", stages: preStages(), writes: []contracts.DataField{contracts.FieldBudget}, reads: []contracts.DataField{contracts.FieldPromptText}})

	if _, err := r.Build(); err == nil {
		t.Fatal("cycle accepted")
	} else if !hasCode(err, domain.CodeInternal) {
		t.Fatalf("err = %v, want error.internal", err)
	}
}

// TestRegistryAfterCycleRejected proves an After cycle is rejected too.
func TestRegistryAfterCycleRejected(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "a", stages: preStages(), after: []string{"b"}})
	mustRegister(t, r, &depGate{id: "b", stages: preStages(), after: []string{"a"}})
	if _, err := r.Build(); err == nil {
		t.Fatal("After cycle accepted")
	}
}

// TestRegistrySelfEdgeIsIgnored proves a gate reading and writing the same field
// does not create a self-cycle.
func TestRegistrySelfEdgeIsIgnored(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "both", stages: preStages(),
		reads: []contracts.DataField{contracts.FieldPromptText}, writes: []contracts.DataField{contracts.FieldPromptText}})
	order, err := r.Build()
	if err != nil {
		t.Fatalf("self-edge produced a cycle: %v", err)
	}
	if got := ids(order.PreRequest); !eq(got, []string{"both"}) {
		t.Fatalf("order = %v", got)
	}
}

// TestRegistryRejectsRegistrationErrors drives every registration guard.
func TestRegistryRejectsRegistrationErrors(t *testing.T) {
	tests := []struct {
		name    string
		reg     func(*Registry) error
		wantBad bool
	}{
		{"empty name", func(r *Registry) error { return r.RegisterGate("", func() contracts.Gate { return nil }) }, true},
		{"nil factory", func(r *Registry) error { return r.RegisterGate("x", nil) }, true},
		{"factory returns nil", func(r *Registry) error { return r.RegisterGate("x", func() contracts.Gate { return nil }) }, true},
		{"id mismatch", func(r *Registry) error {
			return r.RegisterGate("x", func() contracts.Gate { return &depGate{id: "y", stages: preStages()} })
		}, true},
		{"no stage", func(r *Registry) error {
			return r.RegisterGate("x", func() contracts.Gate { return &depGate{id: "x"} })
		}, true},
		{"duplicate", func(r *Registry) error {
			_ = r.RegisterGate("x", func() contracts.Gate { return &depGate{id: "x", stages: preStages()} })
			return r.RegisterGate("x", func() contracts.Gate { return &depGate{id: "x", stages: preStages()} })
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			err := tt.reg(r)
			if tt.wantBad != (err != nil) {
				t.Fatalf("err = %v, wantBad=%v", err, tt.wantBad)
			}
			if err != nil && !hasCode(err, domain.CodeInternal) {
				t.Fatalf("err = %v, want error.internal", err)
			}
		})
	}
}

// TestRegistryRejectsStageMismatch proves a declared stage set that differs from
// Stages() is refused.
func TestRegistryRejectsStageMismatch(t *testing.T) {
	r := NewRegistry()
	g := &mismatchGate{}
	if err := r.RegisterGate("m", func() contracts.Gate { return g }); err == nil {
		t.Fatal("stage mismatch accepted")
	}
}

type mismatchGate struct{ depGate }

func (g *mismatchGate) ID() string { return "m" }
func (g *mismatchGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest, contracts.StagePostResponse)
}
func (g *mismatchGate) Declare() contracts.Declared {
	return contracts.Declared{Stages: contracts.StageSet(contracts.StagePreRequest)}
}

// TestRegistryRejectsFailOpenSecurityWrite proves a FailOpen gate that writes a
// security field is refused (ADR-0014 §3.4).
func TestRegistryRejectsFailOpenSecurityWrite(t *testing.T) {
	for _, f := range []contracts.DataField{contracts.FieldPII, contracts.FieldInjectionFlag} {
		r := NewRegistry()
		g := &depGate{id: "sec", stages: preStages(), policy: contracts.FailOpen, writes: []contracts.DataField{f}}
		if err := r.RegisterGate("sec", func() contracts.Gate { return g }); err == nil {
			t.Fatalf("FailOpen write of %s accepted", f)
		}
	}
	// FailClosed is fine.
	r := NewRegistry()
	g := &depGate{id: "sec", stages: preStages(), policy: contracts.FailClosed, writes: []contracts.DataField{contracts.FieldPII}}
	if err := r.RegisterGate("sec", func() contracts.Gate { return g }); err != nil {
		t.Fatalf("FailClosed security write refused: %v", err)
	}
}

// TestRegistryRejectsFailClosedPostOnly proves a post-response-only FailClosed
// gate is refused (the stage is always FailOpen).
func TestRegistryRejectsFailClosedPostOnly(t *testing.T) {
	r := NewRegistry()
	g := &depGate{id: "p", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailClosed}
	if err := r.RegisterGate("p", func() contracts.Gate { return g }); err == nil {
		t.Fatal("FailClosed post-only gate accepted")
	}
}

// TestRegistryUnresolvedAfter proves an After naming an unregistered gate fails
// at Build.
func TestRegistryUnresolvedAfter(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "a", stages: preStages(), after: []string{"ghost"}})
	if _, err := r.Build(); err == nil {
		t.Fatal("unresolved After accepted")
	}
}

// TestRegistryBuildSeparatesStages proves the per-stage order is computed
// independently.
func TestRegistryBuildSeparatesStages(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, &depGate{id: "pre", stages: contracts.StageSet(contracts.StagePreRequest)})
	mustRegister(t, r, &depGate{id: "chunk", stages: contracts.StageSet(contracts.StageOnResponseChunk)})
	mustRegister(t, r, &depGate{id: "post", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen})

	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !eq(ids(order.PreRequest), []string{"pre"}) {
		t.Fatalf("pre = %v", ids(order.PreRequest))
	}
	if !eq(ids(order.OnResponseChunk), []string{"chunk"}) {
		t.Fatalf("chunk = %v", ids(order.OnResponseChunk))
	}
	if !eq(ids(order.PostResponse), []string{"post"}) {
		t.Fatalf("post = %v", ids(order.PostResponse))
	}
	if !eq(ids(order.All), []string{"chunk", "post", "pre"}) {
		t.Fatalf("all = %v, want ID-sorted", ids(order.All))
	}
}

// TestRegistryBuildCycleInNonPreStage proves a cycle in a NON-pre stage is
// rejected too (the per-stage Build wrappers each surface the error).
func TestRegistryBuildCycleInNonPreStage(t *testing.T) {
	for _, stages := range []contracts.GateStageSet{
		contracts.StageSet(contracts.StageOnResponseChunk),
		contracts.StageSet(contracts.StagePostResponse),
	} {
		r := NewRegistry()
		// Both gates are FailOpen so the post-only FailClosed guard does not fire.
		a := &depGate{id: "a", stages: stages, policy: contracts.FailOpen,
			writes: []contracts.DataField{contracts.FieldPromptText}, reads: []contracts.DataField{contracts.FieldBudget}}
		b := &depGate{id: "b", stages: stages, policy: contracts.FailOpen,
			writes: []contracts.DataField{contracts.FieldBudget}, reads: []contracts.DataField{contracts.FieldPromptText}}
		_ = r.RegisterGate("a", func() contracts.Gate { return a })
		_ = r.RegisterGate("b", func() contracts.Gate { return b })
		if _, err := r.Build(); err == nil {
			t.Fatalf("cycle in stage %v accepted", stages)
		}
	}
}

// TestRegistryEmptyBuild proves an empty registry builds an empty order.
func TestRegistryEmptyBuild(t *testing.T) {
	order, err := NewRegistry().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(order.All) != 0 || len(order.PreRequest) != 0 {
		t.Fatalf("order = %+v", order)
	}
}

// TestLoggerDeclaresAndIsOrdered proves the built-in logger registers, declares
// no data edge, and orders by ID.
func TestLoggerDeclaresAndIsOrdered(t *testing.T) {
	r := NewRegistry()
	if err := r.RegisterGate("logger", func() contracts.Gate { return NewLogger(nil) }); err != nil {
		t.Fatalf("RegisterGate: %v", err)
	}
	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !eq(ids(order.All), []string{"logger"}) {
		t.Fatalf("all = %v", ids(order.All))
	}
}

// mustRegister registers a depGate under its ID, failing the test on error.
func mustRegister(t *testing.T, r *Registry, g *depGate) {
	t.Helper()
	if err := r.RegisterGate(g.id, func() contracts.Gate { return g }); err != nil {
		t.Fatalf("RegisterGate(%s): %v", g.id, err)
	}
}

// hasCode reports whether err is a DomainError with the given code.
func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}
