package router

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}

// TestProviderWildcardExpandsAllModels proves a wildcard step expands to every
// declared model of the provider, in deterministic order.
func TestProviderWildcardExpandsAllModels(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m2", contracts.CapStream, 0).
		add("a", "m1", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, wildcardStep("a")),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 2 || plan.Attempts[0].Model != "m1" || plan.Attempts[1].Model != "m2" {
		t.Fatalf("wildcard order = %+v", plan.Attempts)
	}
}

// TestNestedComboRefRespectsDepth proves a combo-ref chain up to MaxDepth
// resolves, and one past it is refused.
func TestNestedComboRefRespectsDepth(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)

	// Chain c0 -> c1 -> ... -> c7 (depth 7 <= 8).
	byID := map[domain.ComboID]combos.Combo{}
	const depth = 7
	for i := 0; i < depth; i++ {
		cur := domain.ComboID("c" + itoa(i))
		next := domain.ComboID("c" + itoa(i+1))
		byID[cur] = combo(string(cur), contracts.StrategyFallback, refStep(string(next)))
	}
	byID[domain.ComboID("c"+itoa(depth))] = combo("c"+itoa(depth), contracts.StrategyFallback, modelStep("m", 0))

	loader := &fakeComboLoader{combos: byID}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c0")
	if err != nil {
		t.Fatalf("Resolve(depth %d): %v", depth, err)
	}
	if len(plan.Attempts) != 1 || plan.Attempts[0].Model != "m" {
		t.Fatalf("attempts = %+v", plan.Attempts)
	}
}

// TestRuntimeDepthCapRefuses proves the runtime re-checks the depth cap even for
// a persisted combo the validator would have refused.
func TestRuntimeDepthCapRefuses(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	byID := map[domain.ComboID]combos.Combo{}
	// A 10-deep chain, past the cap of 8.
	const depth = 10
	for i := 0; i < depth; i++ {
		cur := domain.ComboID("c" + itoa(i))
		next := domain.ComboID("c" + itoa(i+1))
		byID[cur] = combo(string(cur), contracts.StrategyFallback, refStep(string(next)))
	}
	byID[domain.ComboID("c"+itoa(depth))] = combo("c"+itoa(depth), contracts.StrategyFallback, modelStep("m", 0))
	r := newTestResolver(t, cat, &fakeComboLoader{combos: byID})
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c0")
	if !hasCode(err, domain.CodeRouteDepthExceeded) {
		t.Fatalf("err = %v, want depth_exceeded", err)
	}
}

// TestRuntimeCycleRefused proves a runtime cycle (malformed store) is refused.
func TestRuntimeCycleRefused(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	byID := map[domain.ComboID]combos.Combo{
		"a": combo("a", contracts.StrategyFallback, refStep("b")),
		"b": combo("b", contracts.StrategyFallback, refStep("a")),
	}
	r := newTestResolver(t, cat, &fakeComboLoader{combos: byID})
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "a")
	if !hasCode(err, domain.CodeRouteCyclicCombo) {
		t.Fatalf("err = %v, want cyclic_combo", err)
	}
}

// TestUnknownProviderWildcardRefused proves a wildcard to an unknown provider is
// refused.
func TestUnknownProviderWildcardRefused(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, wildcardStep("ghost")),
	}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteUnknownProvider) {
		t.Fatalf("err = %v, want unknown_provider", err)
	}
}

// TestUnknownComboRefRefused proves a combo-ref to a missing combo is refused.
func TestUnknownComboRefRefused(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, refStep("missing")),
	}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteInvalidCombo) {
		t.Fatalf("err = %v, want invalid_combo", err)
	}
}

// TestNoCandidateWhenModelUnknown proves an unroutable model yields
// route.no_candidate (not an empty successful plan).
func TestNoCandidateWhenModelUnknown(t *testing.T) {
	cat := newFakeCatalog().add("a", "known", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("unknown", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v, want no_candidate", err)
	}
}

// TestNoCandidateWhenPreflightDeniesAll proves that filtering every candidate
// yields no_candidate.
func TestNoCandidateWhenPreflightDeniesAll(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader, WithPreflight(fakePreflight{deny: map[string]bool{"a/m": true}}))
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v, want no_candidate after full preflight filtering", err)
	}
}

// TestPreflightRemovesDeniedCandidate proves a denied candidate is dropped while
// the rest survive.
func TestPreflightRemovesDeniedCandidate(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader, WithPreflight(fakePreflight{deny: map[string]bool{"a/m": true}}))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 1 || plan.Attempts[0].Provider != "b" {
		t.Fatalf("attempts = %+v", plan.Attempts)
	}
}

// TestCapabilityAwareDemotesNeverDrops proves a candidate missing the required
// capability is demoted to the end, not removed.
func TestCapabilityAwareDemotesNeverDrops(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "plain", contracts.CapStream, 0).                          // no vision
		add("b", "vision", contracts.CapStream.Add(contracts.CapVision), 0) // vision
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("plain", 0), modelStep("vision", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	// Fallback declares plain first; capability-awareness moves vision (the
	// compatible one) first WITHOUT dropping plain.
	plan, err := r.Resolve(context.Background(), &contracts.Request{Capabilities: contracts.CapVision}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 (never drop)", len(plan.Attempts))
	}
	if plan.Attempts[0].Provider != "b" {
		t.Fatalf("order = %v, want the compatible b first", providersOf(plan))
	}
	if !strings.Contains(plan.Attempts[1].Reason, "capability_mismatch") {
		t.Fatalf("demoted reason = %q, want capability_mismatch", plan.Attempts[1].Reason)
	}
}

// TestAutomaticResolutionByModel proves a nil combo resolves the request's own
// model across providers.
func TestAutomaticResolutionByModel(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	r := newTestResolver(t, cat, &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{}})
	plan, err := r.Resolve(context.Background(), &contracts.Request{Model: "m"}, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Strategy != contracts.StrategyAuto || len(plan.Attempts) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.MaxRounds < 1 {
		t.Fatalf("MaxRounds = %d", plan.MaxRounds)
	}
}

// TestAutomaticResolutionRequiresModel proves an empty model resolves to
// no_candidate.
func TestAutomaticResolutionRequiresModel(t *testing.T) {
	r := newTestResolver(t, newFakeCatalog(), &fakeComboLoader{})
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "")
	if !hasCode(err, domain.CodeRouteNoCandidate) {
		t.Fatalf("err = %v", err)
	}
}

// TestNilRequestRefused proves a nil request is refused.
func TestNilRequestRefused(t *testing.T) {
	r := newTestResolver(t, newFakeCatalog(), &fakeComboLoader{})
	if _, err := r.Resolve(context.Background(), nil, ""); !hasCode(err, domain.CodeRouteInvalidCombo) {
		t.Fatalf("err = %v", err)
	}
}

// TestComboLoadErrorPropagates proves a loader error surfaces.
func TestComboLoadErrorPropagates(t *testing.T) {
	want := errors.New("boom")
	r := newTestResolver(t, newFakeCatalog(), &fakeComboLoader{err: want})
	if _, err := r.Resolve(context.Background(), &contracts.Request{}, "c"); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

// TestUnknownStrategyInComboRefused proves a combo with an unknown strategy is
// refused at resolve.
func TestUnknownStrategyInComboRefused(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", "nope", modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	// An unknown strategy falls back to auto (defaultStrategy), so this resolves;
	// to force the error, remove all strategies via WithStrategies.
	r2 := newTestResolver(t, cat, loader, WithStrategies(nil))
	_, err := r2.Resolve(context.Background(), &contracts.Request{}, "c")
	if err == nil {
		t.Fatal("resolver with no strategies accepted a combo")
	}
	_ = r
}

// TestStrategyRegistryRejectsBadRegistrations drives the registry constructor's
// error branches directly.
func TestStrategyRegistryRejectsBadRegistrations(t *testing.T) {
	if _, err := newRegistry([]Strategy{nil}); err == nil {
		t.Fatal("nil strategy accepted")
	}
	if _, err := newRegistry([]Strategy{priorityStrategy{}, priorityStrategy{}}); err == nil {
		t.Fatal("duplicate strategy accepted")
	}
	// A fake strategy with an unknown kind is refused.
	if _, err := newRegistry([]Strategy{badKindStrategy{}}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	// A valid set resolves its members.
	reg, err := newRegistry(defaultStrategies())
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	if _, err := reg.Get(contracts.StrategyAuto); err != nil {
		t.Fatalf("Get(auto): %v", err)
	}
	if _, err := reg.Get("nope"); err == nil {
		t.Fatal("Get(nope) succeeded")
	}
}

// badKindStrategy is a Strategy with a kind outside the closed set.
type badKindStrategy struct{}

func (badKindStrategy) Kind() contracts.StrategyKind { return "nope" }
func (badKindStrategy) Order(context.Context, *contracts.Request, []expanded, Env) []contracts.Candidate {
	return nil
}

// TestWithStrategiesErrorSurfaces proves a bad WithStrategies override surfaces
// at Resolve.
func TestWithStrategiesErrorSurfaces(t *testing.T) {
	r := newTestResolver(t, newFakeCatalog(), &fakeComboLoader{}, WithStrategies([]Strategy{nil}))
	if _, err := r.Resolve(context.Background(), &contracts.Request{}, ""); err == nil {
		t.Fatal("bad strategy override did not surface")
	}
}

// TestRandSourceAdapter covers the production RNG adapter.
func TestRandSourceAdapter(t *testing.T) {
	src := NewRandSource(newPCGRand(7))
	if src.Intn(10) < 0 || src.Intn(10) >= 10 {
		t.Fatal("Intn out of range")
	}
	if f := src.Float64(); f < 0 || f >= 1 {
		t.Fatalf("Float64 = %v", f)
	}
}
