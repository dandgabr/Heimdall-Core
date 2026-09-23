package token

import (
	"context"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeEngine is a scriptable CompressionEngine for the registry/gate tests.
type fakeEngine struct {
	id     string
	impact CacheImpact
	lossy  bool
	apply  func([]byte, Options) ([]byte, Stats, error)
}

func (e fakeEngine) ID() string               { return e.id }
func (e fakeEngine) CacheImpact() CacheImpact { return e.impact }
func (e fakeEngine) Lossy() bool              { return e.lossy }
func (e fakeEngine) Apply(in []byte, o Options) ([]byte, Stats, error) {
	if e.apply != nil {
		return e.apply(in, o)
	}
	return in, Stats{ID: e.id, BytesIn: len(in), BytesOut: len(in)}, nil
}

func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}

// TestRegistryRegistersValidEnginesAndOrders proves a valid registration is kept
// and Enabled returns engines in ID order.
func TestRegistryRegistersValidEnginesAndOrders(t *testing.T) {
	r := NewRegistry()
	mustEngine(t, r, fakeEngine{id: "zeta", impact: ImpactLow, lossy: true}, false)
	mustEngine(t, r, fakeEngine{id: "alpha", impact: ImpactNone, lossy: false}, false)
	got := r.Enabled()
	if len(got) != 2 || got[0].ID() != "alpha" || got[1].ID() != "zeta" {
		t.Fatalf("Enabled = %v", idsOf(got))
	}
}

func idsOf(es []CompressionEngine) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID()
	}
	return out
}

// TestRegistryRejectsBadEngines drives every ADR-0015 §1 guard.
func TestRegistryRejectsBadEngines(t *testing.T) {
	cases := []struct {
		name     string
		e        CompressionEngine
		optIn    bool
		wantCode bool
	}{
		{"nil", nil, false, true},
		{"empty id", fakeEngine{id: "", impact: ImpactLow}, false, true},
		{"lossy impact-none", fakeEngine{id: "x", lossy: true, impact: ImpactNone}, false, true},
		{"unknown impact", fakeEngine{id: "x", impact: CacheImpact(99)}, false, true},
		{"opt-in without high", fakeEngine{id: "x", impact: ImpactLow}, true, true},
		{"valid high with opt-in", fakeEngine{id: "x", impact: ImpactHigh, lossy: true}, true, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			err := r.Register(tt.e, tt.optIn)
			if (err != nil) != tt.wantCode {
				t.Fatalf("err = %v, wantErr=%v", err, tt.wantCode)
			}
			if err != nil && !hasCode(err, domain.CodeInternal) {
				t.Fatalf("err = %v, want error.internal", err)
			}
		})
	}
}

// TestRegistryRejectsDuplicate proves a duplicate ID is refused.
func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	mustEngine(t, r, fakeEngine{id: "dup", impact: ImpactLow}, false)
	if err := r.Register(fakeEngine{id: "dup", impact: ImpactLow}, false); err == nil {
		t.Fatal("duplicate accepted")
	}
}

// TestRegistryAllowPrefixRewrite proves the opt-in is remembered per engine.
func TestRegistryAllowPrefixRewrite(t *testing.T) {
	r := NewRegistry()
	mustEngine(t, r, fakeEngine{id: "high", impact: ImpactHigh, lossy: true}, true)
	mustEngine(t, r, fakeEngine{id: "low", impact: ImpactLow, lossy: true}, false)
	if !r.AllowPrefixRewrite("high") {
		t.Fatal("high opt-in lost")
	}
	if r.AllowPrefixRewrite("low") || r.AllowPrefixRewrite("ghost") {
		t.Fatal("unexpected opt-in")
	}
}

// mustEngine registers an engine, failing on error.
func mustEngine(t *testing.T, r *Registry, e CompressionEngine, optIn bool) {
	t.Helper()
	if err := r.Register(e, optIn); err != nil {
		t.Fatalf("Register(%s): %v", e.ID(), err)
	}
}

// TestGateMetadataAndContract pins the gate's identity, stage, policy, body need
// and declared graph edges.
func TestGateMetadataAndContract(t *testing.T) {
	g := New(Config{Engines: []CompressionEngine{NewCountOnly()}})
	if g.ID() != "token" {
		t.Fatalf("ID = %q", g.ID())
	}
	if !g.Stages().Has(contracts.StagePreRequest) || g.Stages().Has(contracts.StageOnResponseChunk) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.FailurePolicy() != contracts.FailOpen {
		t.Fatalf("policy = %v, want FailOpen", g.FailurePolicy())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v, want 0", g.RequiredCaps())
	}
	if !g.NeedsBody() {
		t.Fatal("gate must declare it needs the body")
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	d := g.Declare()
	if d.Stages != g.Stages() {
		t.Fatalf("declared stages mismatch")
	}
	if !contains(d.Reads, contracts.FieldContext) || !contains(d.Reads, contracts.FieldCacheLookup) {
		t.Fatalf("reads = %v, want context+cache_lookup", d.Reads)
	}
	if !contains(d.Writes, contracts.FieldPromptText) || !contains(d.Writes, contracts.FieldPrefixRange) {
		t.Fatalf("writes = %v, want prompt_text+prefix_range", d.Writes)
	}
}

func contains(fs []contracts.DataField, want contracts.DataField) bool {
	for _, f := range fs {
		if f == want {
			return true
		}
	}
	return false
}

// TestGateCompressesSuffixKeepsPrefix is the central integration: the gate
// compresses the suffix and returns DecisionModify, and the frozen prefix is
// byte-identical after the gate.
func TestGateCompressesSuffixKeepsPrefix(t *testing.T) {
	var stats []Stats
	g := New(Config{Engines: []CompressionEngine{NewCollapseWhitespace()}, Record: func(s Stats) { stats = append(stats, s) }})
	in := pretty("SYS   A", "user    B")
	end := prefixBoundary(in)
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in, Model: "m"})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionModify {
		t.Fatalf("decision = %v, want Modify", d.Kind)
	}
	if len(d.Body) >= len(in) {
		t.Fatalf("no compression: %d vs %d", len(d.Body), len(in))
	}
	if string(in[:end]) != string(d.Body[:end]) {
		t.Fatalf("prefix changed:\n in=%q\nout=%q", in[:end], d.Body[:end])
	}
	if len(stats) != 1 || !stats[0].Applied() {
		t.Fatalf("stats = %+v", stats)
	}
	// The stats carry counts only, never content.
	for _, s := range stats {
		if s.ID == "" || s.BytesIn == 0 {
			t.Fatalf("stats incomplete: %+v", s)
		}
	}
}

// TestGatePrefixIntactWithoutOptIn proves an ImpactHigh engine without opt-in
// does not touch the prefix.
func TestGatePrefixIntactWithoutOptIn(t *testing.T) {
	g := New(Config{Engines: []CompressionEngine{NewPrefixRewrite()}})
	in := pretty("SYS   A", "user    B")
	end := prefixBoundary(in)
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionModify {
		t.Fatalf("decision = %v", d.Kind)
	}
	if string(in[:end]) != string(d.Body[:end]) {
		t.Fatalf("prefix touched without opt-in")
	}
}

// TestGatePrefixMayChangeWithOptIn proves that with opt-in the frozen prefix may
// change (the operator's explicit decision).
func TestGatePrefixMayChangeWithOptIn(t *testing.T) {
	g := New(Config{
		Engines: []CompressionEngine{NewPrefixRewrite()},
		OptIn:   map[string]bool{"prefix-rewrite": true},
	})
	in := pretty("SYS   A", "user    B")
	end := prefixBoundary(in)
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionModify {
		t.Fatalf("decision = %v", d.Kind)
	}
	if string(in[:end]) == string(d.Body[:end]) {
		t.Fatal("opt-in did not allow prefix rewrite")
	}
	if len(d.Body) >= len(in) {
		t.Fatal("opt-in produced no compression")
	}
}

// TestGateRejectsEngineThatBreaksPrefix proves the gate DISCARDS the change of a
// non-opt-in engine that (incorrectly) rewrites the prefix.
func TestGateRejectsEngineThatBreaksPrefix(t *testing.T) {
	// A malicious/buggy engine that collapses the WHOLE body regardless of
	// PrefixEnd.
	rogue := fakeEngine{id: "rogue", impact: ImpactLow, lossy: true, apply: func(in []byte, _ Options) ([]byte, Stats, error) {
		out := collapseRuns(in)
		return out, Stats{ID: "rogue", BytesIn: len(in), BytesOut: len(out)}, nil
	}}
	g := New(Config{Engines: []CompressionEngine{rogue}})
	in := pretty("SYS   A", "user    B")
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	// The prefix-rewrite change is rejected, so the gate made no change at all.
	if d.Kind != contracts.DecisionContinue {
		t.Fatalf("decision = %v, want Continue (rogue change discarded)", d.Kind)
	}
}

// TestGateRejectsInvalidJSON proves an engine that produces a non-JSON body is
// discarded.
func TestGateRejectsInvalidJSON(t *testing.T) {
	// The output keeps the frozen prefix byte-identical (so it passes the prefix
	// check) but is not valid JSON, exercising the JSON validation branch.
	breaker := fakeEngine{id: "bad", impact: ImpactLow, lossy: true, apply: func(in []byte, _ Options) ([]byte, Stats, error) {
		out := append([]byte{}, in...)
		// Append a stray trailing token: length grows (prefix preserved), but the
		// body no longer parses as a single JSON object.
		out = append(out, []byte(" trailing")...)
		return out, Stats{ID: "bad", BytesIn: len(in), BytesOut: len(out)}, nil
	}}
	g := New(Config{Engines: []CompressionEngine{breaker}})
	in := pretty("SYS", "user")
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionContinue {
		t.Fatalf("decision = %v, want Continue (invalid JSON discarded)", d.Kind)
	}
}

// TestGateFailOpenOnEngineError proves a failing engine never breaks the
// request: the gate continues and keeps the body.
func TestGateFailOpenOnEngineError(t *testing.T) {
	boom := fakeEngine{id: "boom", impact: ImpactLow, lossy: true, apply: func([]byte, Options) ([]byte, Stats, error) {
		return nil, Stats{}, errors.New("engine exploded")
	}}
	g := New(Config{Engines: []CompressionEngine{boom, NewCountOnly()}})
	in := pretty("SYS", "user")
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: in})
	if err != nil {
		t.Fatalf("a FailOpen engine error propagated: %v", err)
	}
	if d.Kind != contracts.DecisionContinue || d.Body != nil {
		t.Fatalf("decision = %+v, want Continue with no body", d)
	}
}

// TestGateEmptyInputsAreContinue proves the trivial guard branches.
func TestGateEmptyInputsAreContinue(t *testing.T) {
	// No engines.
	g := New(Config{})
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{"a":1}`)})
	if err != nil || d.Kind != contracts.DecisionContinue {
		t.Fatalf("no engines: %+v, %v", d, err)
	}
	// Nil/empty body.
	g2 := New(Config{Engines: []CompressionEngine{NewCountOnly()}})
	d2, err := g2.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil || d2.Kind != contracts.DecisionContinue {
		t.Fatalf("no body: %+v, %v", d2, err)
	}
	// A nil engine in the slice is skipped.
	g3 := New(Config{Engines: []CompressionEngine{nil, NewCountOnly()}})
	if _, err := g3.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{"a":1}`)}); err != nil {
		t.Fatalf("nil engine: %v", err)
	}
}

// TestGateNoopEngineYieldsContinue proves that an engine that does not change
// the body yields Continue (no spurious Modify).
func TestGateNoopEngineYieldsContinue(t *testing.T) {
	g := New(Config{Engines: []CompressionEngine{NewCountOnly()}})
	d, err := g.PreRequest(context.Background(), contracts.GateInput{Body: pretty("SYS", "user")})
	if err != nil || d.Kind != contracts.DecisionContinue {
		t.Fatalf("decision = %+v, %v", d, err)
	}
}

// TestGateChunkAndCloseArePassThrough proves the non-PreRequest methods are
// inert pass-through.
func TestGateChunkAndCloseArePassThrough(t *testing.T) {
	g := New(Config{})
	cd, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{Body: []byte("x")})
	if err != nil || cd.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk = %+v, %v", cd, err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestGatePostResponseCacheSignal proves the cache-hit signal is reported when
// present, and ignored otherwise.
func TestGatePostResponseCacheSignal(t *testing.T) {
	var got []Stats
	g := New(Config{Record: func(s Stats) { got = append(got, s) }})

	// No Derived, no signal.
	if err := g.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	// Derived without the key.
	if err := g.PostResponse(context.Background(), contracts.GateInput{Derived: &contracts.Derived{Fields: map[string]string{}}}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	// Present and numeric.
	if err := g.PostResponse(context.Background(), contracts.GateInput{Derived: &contracts.Derived{Fields: map[string]string{"cached_tokens": "42"}}}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	// Present but non-numeric (ignored).
	if err := g.PostResponse(context.Background(), contracts.GateInput{Derived: &contracts.Derived{Fields: map[string]string{"cached_tokens": "abc"}}}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	if len(got) != 1 || got[0].TokensSaved != 42 {
		t.Fatalf("cache signal = %+v", got)
	}
}

// TestGatePostResponseNilRecorder covers the nil-recorder guard.
func TestGatePostResponseNilRecorder(t *testing.T) {
	g := New(Config{})
	if err := g.PostResponse(context.Background(), contracts.GateInput{Derived: &contracts.Derived{Fields: map[string]string{"cached_tokens": "1"}}}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
}

// TestAcceptOutputShortenedPrefix proves the branch where the engine made the
// output SHORTER than the frozen prefix (a direct rejection).
func TestAcceptOutputShortenedPrefix(t *testing.T) {
	g := New(Config{})
	before := []byte(`{"messages":[{"role":"user","content":"x"}]}`)
	end := prefixBoundary(before)
	if end <= 0 {
		t.Skip("test body has no prefix")
	}
	after := []byte(`{}`) // shorter than the prefix
	opts := Options{PrefixEnd: end}
	if g.acceptOutput(before, after, NewCountOnly(), opts) {
		t.Fatal("acceptOutput accepted an output shorter than the frozen prefix")
	}
}

// TestAcceptOutputPrefixEndBeyondLen clamps the end safely.
func TestAcceptOutputPrefixEndBeyondLen(t *testing.T) {
	g := New(Config{})
	before := []byte(`{"a":1}`)
	after := []byte(`{"a":1}`)
	if !g.acceptOutput(before, after, NewCountOnly(), Options{PrefixEnd: 999}) {
		t.Fatal("a matching body beyond the prefix was rejected")
	}
}

// TestGateStatsDefaultFilling covers the stats-completion branches: an engine
// that leaves ID/BytesIn/BytesOut zero.
func TestGateStatsDefaultFilling(t *testing.T) {
	// An engine that changes the body but reports NO stats: the gate completes
	// the counts from the actual values.
	var got Stats
	changer := fakeEngine{id: "changer", impact: ImpactLow, lossy: true, apply: func([]byte, Options) ([]byte, Stats, error) {
		return []byte(`{"trimmed":true}`), Stats{}, nil
	}}
	g := New(Config{Engines: []CompressionEngine{changer}, Record: func(s Stats) { got = s }})
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{"original":true}`)}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if got.ID != "changer" || got.BytesIn == 0 || got.BytesOut == 0 {
		t.Fatalf("stats not completed: %+v", got)
	}
}
