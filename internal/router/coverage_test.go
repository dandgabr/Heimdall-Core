package router

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestCursorBranches covers the cursor's guard branches directly (n<=0 and the
// out-of-range reset).
func TestCursorBranches(t *testing.T) {
	var c Cursor
	if c.nextRR("k", 0) != 0 {
		t.Fatal("nextRR with n=0 should return 0")
	}
	if c.nextFill("k", 0) != 0 {
		t.Fatal("nextFill with n=0 should return 0")
	}
	// Seed an out-of-range index and confirm it resets to 0.
	c.roundRobin = map[string]int{"k": 99}
	if c.nextRR("k", 2) != 0 {
		t.Fatal("out-of-range round-robin index did not reset")
	}
	c.fillFirst = map[string]int{"k": 99}
	if c.nextFill("k", 2) != 0 {
		t.Fatal("out-of-range fill-first index did not reset")
	}
}

// TestExpandUnknownStepKind covers the expand default branch (a malformed step
// that slipped past validation).
func TestExpandUnknownStepKind(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	bad := combo("bad", contracts.StrategyFallback, combos.Step{Kind: "weird", Ref: "x"})
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{"bad": bad}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "bad")
	if !hasCode(err, domain.CodeRouteInvalidCombo) {
		t.Fatalf("err = %v, want invalid_combo (unknown step kind)", err)
	}
}

// TestWeightedNilRNGFallsBackToWeightOrder covers the weightedDraw nil-RNG
// branch with DIFFERENT weights (so the weight comparison runs).
func TestWeightedNilRNGFallsBackToWeightOrder(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyWeighted,
			combos.Step{Kind: combos.StepProviderWildcard, Ref: "a", Weight: 1},
			combos.Step{Kind: combos.StepProviderWildcard, Ref: "b", Weight: 5}),
	}}
	r := newTestResolver(t, cat, loader) // no RNG
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// b has the higher weight, so the deterministic fallback puts b first.
	if plan.Attempts[0].Provider != "b" {
		t.Fatalf("weighted nil-RNG order = %v, want b first", providersOf(plan))
	}
}

// TestBetterPressureWithoutSignals covers the nil-Signals branch.
func TestBetterPressureWithoutSignals(t *testing.T) {
	if got := betterPressure(context.Background(), Env{}, expanded{}, expanded{}); got != 0 {
		t.Fatalf("betterPressure without signals = %d, want 0", got)
	}
}

// TestAutoScoreWithoutSignalsOrCost covers the neutral defaults and the
// cost-known branch.
func TestAutoScoreWithoutSignalsOrCost(t *testing.T) {
	if _, notes := autoScore(context.Background(), Env{}, contracts.Candidate{Provider: "a", Model: "m"}); notes == "" {
		t.Fatal("autoScore without signals produced no notes")
	}
	// A known cost exercises the cost-normalization branch.
	cost := fakeCost{m: map[string]int64{"a/m": 25}}
	if _, notes := autoScore(context.Background(), Env{Cost: cost}, contracts.Candidate{Provider: "a", Model: "m"}); notes == "" {
		t.Fatal("autoScore with cost produced no notes")
	}
	// A zero cost (unknown/0) takes the non-positive branch.
	costZero := fakeCost{m: map[string]int64{"a/m": 0}}
	_, _ = autoScore(context.Background(), Env{Cost: costZero}, contracts.Candidate{Provider: "a", Model: "m"})
}

// TestClamp01AndItoa64 cover the small helpers' branches.
func TestClamp01AndItoa64(t *testing.T) {
	if clamp01(-1) != 0 || clamp01(2) != 1 || clamp01(0.5) != 0.5 {
		t.Fatal("clamp01 wrong")
	}
	if itoa64(0) != "0" || itoa64(42) != "42" || itoa64(-7) != "-7" {
		t.Fatalf("itoa64: %q %q %q", itoa64(0), itoa64(42), itoa64(-7))
	}
}

// TestExpandNestedEmptyRefStillParentTier covers a combo-ref whose referenced
// combo yields no candidates for the request (a model no provider declares).
func TestExpandNestedEmptyRefStillParentTier(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	byID := map[domain.ComboID]combos.Combo{
		"top": combo("top", contracts.StrategyFallback, refStep("mid"), modelStep("m", 0)),
		"mid": combo("mid", contracts.StrategyFallback, modelStep("absent", 0)),
	}
	r := newTestResolver(t, cat, &fakeComboLoader{combos: byID})
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "top")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 1 || plan.Attempts[0].Model != "m" {
		t.Fatalf("attempts = %+v", plan.Attempts)
	}
}

// TestComboListErrorPropagates proves a List error surfaces (the nested lookup).
func TestComboListErrorPropagates(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &listErrorLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err == nil {
		t.Fatal("expected the List error")
	}
}

// listErrorLoader returns an error only from List.
type listErrorLoader struct {
	combos map[domain.ComboID]combos.Combo
}

func (l *listErrorLoader) Get(_ context.Context, id domain.ComboID) (combos.Combo, error) {
	c, ok := l.combos[id]
	if !ok {
		return combos.Combo{}, combos.ErrNotFound
	}
	return c, nil
}

func (l *listErrorLoader) List(context.Context) ([]combos.Combo, error) {
	return nil, domain.New(domain.CodeInternal, domain.WithHTTPStatus(500))
}

// TestNewRegistryConstructionError covers New's construction-error branch via
// the injectable strategy list.
func TestNewRegistryConstructionError(t *testing.T) {
	old := defaultStrategyList
	defaultStrategyList = func() []Strategy { return []Strategy{nil} }
	t.Cleanup(func() { defaultStrategyList = old })

	if _, err := New(&fakeComboLoader{}, newFakeCatalog()); err == nil {
		t.Fatal("New accepted a malformed built-in strategy list")
	}
}

// TestResolveAutoNoProviderDeclares covers resolveAuto's continue branch (a
// provider that does not declare the model).
func TestResolveAutoNoProviderDeclares(t *testing.T) {
	// Two providers; only one declares the model.
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "other", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{})
	plan, err := r.Resolve(context.Background(), &contracts.Request{Model: "m"}, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 1 || plan.Attempts[0].Provider != "a" {
		t.Fatalf("attempts = %+v", plan.Attempts)
	}
}

// TestResolveAutoPreflightEmptiesAll covers resolveAuto's empty-after-preflight
// branch.
func TestResolveAutoPreflightEmptiesAll(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{}, WithPreflight(fakePreflight{deny: map[string]bool{"a/m": true}}))
	_, err := r.Resolve(context.Background(), &contracts.Request{Model: "m"}, "")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v", err)
	}
}

// TestMaxRoundsDefaultFloor covers the default branch's n<1 floor.
func TestMaxRoundsDefaultFloor(t *testing.T) {
	if got := maxRoundsFor(contracts.StrategyAuto, combos.Combo{}, 0); got != 1 {
		t.Fatalf("maxRoundsFor(auto, n=0) = %d, want 1", got)
	}
}

// TestBuildFusionPlansEmpty covers the empty-ordered guard.
func TestBuildFusionPlansEmpty(t *testing.T) {
	r := newTestResolver(t, newFakeCatalog(), &fakeComboLoader{})
	if _, err := r.buildFusionPlans(context.Background(), &contracts.Request{}, "c", nil, nil); !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v, want no_candidate", err)
	}
}

// TestTieBreaksByStableKey exercises the stable-key sub-comparators: two
// candidates with the SAME step (priority/fallback/pipeline/fusion) but
// different providers, and two with the same provider but different models.
func TestTieBreaksByStableKey(t *testing.T) {
	cat := newFakeCatalog().
		add("b", "m", contracts.CapStream, 0).
		add("a", "m", contracts.CapStream, 0).
		add("a", "z", contracts.CapStream, 0)
	for _, kind := range []contracts.StrategyKind{
		contracts.StrategyPriority, contracts.StrategyFallback,
		contracts.StrategyPipeline, contracts.StrategyFusion,
	} {
		loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
			// One wildcard over a, one model over m (declared by a and b): same
			// step => tie on step, resolved by the stable key.
			"c": combo("c", kind, combos.Step{Kind: combos.StepProviderWildcard, Ref: "a"}),
		}}
		r := newTestResolver(t, cat, loader)
		plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
		if err != nil {
			t.Fatalf("%s: Resolve: %v", kind, err)
		}
		// a/m before a/z (same provider, model tie-break).
		if plan.Attempts[0].Model != "m" || plan.Attempts[1].Model != "z" {
			t.Fatalf("%s: tie-break = %+v", kind, plan.Attempts)
		}
	}
}

// TestCostTieBreak covers the cost comparator's stable-key fallback (two models
// with the SAME known price).
func TestCostTieBreak(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "x", contracts.CapStream, 0).
		add("a", "y", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyCost, modelStep("y", 0), modelStep("x", 0)),
	}}
	cost := fakeCost{m: map[string]int64{"a/x": 5, "a/y": 5}} // equal price
	r := newTestResolver(t, cat, loader, WithCost(cost))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Model != "x" {
		t.Fatalf("equal-cost tie-break = %+v, want x first (stable key)", plan.Attempts)
	}
}

// TestFillFirstProviderTieBreak covers the fill-first comparator's provider and
// stable-key sub-branches.
func TestFillFirstProviderTieBreak(t *testing.T) {
	cat := newFakeCatalog().
		add("b", "m", contracts.CapStream, 0).
		add("a", "m", contracts.CapStream, 0).
		add("a", "z", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFillFirst, modelStep("m", 0), modelStep("z", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The first attempt must be the lexicographically-smallest provider (a).
	if plan.Attempts[0].Provider != "a" {
		t.Fatalf("fill-first order = %v, want a first", providersOf(plan))
	}
}

// TestBetterPressureTieReturnsZero covers the "b not better" branch.
func TestBetterPressureTieReturnsZero(t *testing.T) {
	sig := newFakeSignals()
	sig.quota["a/m"] = 0.9
	sig.quota["b/m"] = 0.1
	// a has lower pressure, so position 0 (no swap) is returned.
	got := betterPressure(context.Background(), Env{Signals: sig},
		expanded{candidate: contracts.Candidate{Provider: "a", Model: "m"}},
		expanded{candidate: contracts.Candidate{Provider: "b", Model: "m"}})
	if got != 0 {
		t.Fatalf("betterPressure = %d, want 0", got)
	}
}

// TestWeightedEqualWeightTie covers the weightedDraw nil-RNG equal-weight branch
// (the `return false` fall-through).
func TestWeightedEqualWeightTie(t *testing.T) {
	group := []expanded{
		{candidate: contracts.Candidate{Provider: "a", Model: "m"}, weight: 2},
		{candidate: contracts.Candidate{Provider: "b", Model: "m"}, weight: 2},
	}
	order := weightedDraw(group, nil)
	if len(order) != 2 {
		t.Fatalf("order = %v", order)
	}
}

// TestResolveAutoPreflightEmpties covers resolveAuto's post-preflight empty
// branch (previously shadowed by the combo path).
func TestResolveAutoPreflightEmpties(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{}, WithPreflight(fakePreflight{deny: map[string]bool{"a/m": true}}))
	_, err := r.Resolve(context.Background(), &contracts.Request{Model: "m"}, "")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v, want no_candidate", err)
	}
}

// TestPriorityDistinctSteps covers the priority comparator's step-difference
// branch (two steps present).
func TestPriorityDistinctSteps(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		// Declare m2 FIRST then m1: priority keeps m2's step first even though a
		// provider sorts before b.
		"c": combo("c", contracts.StrategyPriority, modelStep("m2", 0), modelStep("m1", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Model != "m2" {
		t.Fatalf("priority distinct-step order = %+v, want m2 first", plan.Attempts)
	}
}

// TestFillFirstSameProviderModelTie covers the fill-first comparator's stable-key
// sub-branch (same step AND same provider, different models) using a wildcard
// step, so the two candidates share a step.
func TestFillFirstSameProviderModelTie(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "z", contracts.CapStream, 0).
		add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFillFirst, wildcardStep("a")),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Model != "m" {
		t.Fatalf("fill-first same-provider order = %+v, want m first", plan.Attempts)
	}
}

// TestResolveAutoModelNotDeclared covers resolveAuto's len(expanded)==0 branch.
func TestResolveAutoModelNotDeclared(t *testing.T) {
	cat := newFakeCatalog().add("a", "known", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{})
	_, err := r.Resolve(context.Background(), &contracts.Request{Model: "ghost"}, "")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v, want no_candidate", err)
	}
}

// TestResolveAutoStrategyMissing covers resolveAuto's registry.Get error: an
// injected strategy set that lacks `auto`.
func TestResolveAutoStrategyMissing(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{}, WithStrategies([]Strategy{priorityStrategy{}}))
	_, err := r.Resolve(context.Background(), &contracts.Request{Model: "m"}, "")
	if err == nil {
		t.Fatal("resolveAuto succeeded without the auto strategy")
	}
}
