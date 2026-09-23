package router

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// newTestResolver builds a Resolver over a catalog with two providers and a set
// of combos, plus the given options.
func newTestResolver(t *testing.T, cat ModelCatalog, loader ComboLoader, opts ...Option) *Resolver {
	t.Helper()
	r, err := New(loader, cat, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// providersOf extracts the provider order from a plan.
func providersOf(plan contracts.RoutePlan) []domain.ProviderID {
	out := make([]domain.ProviderID, 0, len(plan.Attempts))
	for _, c := range plan.Attempts {
		out = append(out, c.Provider)
	}
	return out
}

// TestPriorityOrdersEarlierStepFirst proves priority uses the declared order.
func TestPriorityOrdersEarlierStepFirst(t *testing.T) {
	cat := newFakeCatalog().
		add("z.ai", "m1", contracts.CapStream, 0).
		add("ollama", "m1", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyPriority, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{Model: "m1"}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Strategy != contracts.StrategyPriority {
		t.Fatalf("strategy = %v", plan.Strategy)
	}
	// m2 is declared second and no provider declares it, so only m1 candidates.
	// Providers are ordered by the stable key: ollama before z.ai.
	got := providersOf(plan)
	if len(got) != 2 || got[0] != "ollama" || got[1] != "z.ai" {
		t.Fatalf("order = %v", got)
	}
}

// TestFallbackKeepsDeclaredOrder proves fallback does not reorder by health.
func TestFallbackKeepsDeclaredOrder(t *testing.T) {
	cat := newFakeCatalog().
		add("z.ai", "m1", contracts.CapStream, 0).
		add("z.ai", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFallback, modelStep("m2", 0), modelStep("m1", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Declared order: m2 then m1.
	if len(plan.Attempts) != 2 || plan.Attempts[0].Model != "m2" || plan.Attempts[1].Model != "m1" {
		t.Fatalf("order = %+v", plan.Attempts)
	}
}

// TestRoundRobinRotates proves the cursor rotates and wraps.
func TestRoundRobinRotates(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyRoundRobin, modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader)

	first, _ := r.Resolve(context.Background(), &contracts.Request{}, "c")
	second, _ := r.Resolve(context.Background(), &contracts.Request{}, "c")
	third, _ := r.Resolve(context.Background(), &contracts.Request{}, "c")

	if first.Attempts[0].Provider != "a" {
		t.Fatalf("first = %v", providersOf(first))
	}
	if second.Attempts[0].Provider != "b" {
		t.Fatalf("second = %v", providersOf(second))
	}
	if third.Attempts[0].Provider != "a" {
		t.Fatalf("third (wrap) = %v", providersOf(third))
	}

	// A NEW resolver (a "new process") starts at index 0 again (documented).
	r2 := newTestResolver(t, cat, loader)
	fresh, _ := r2.Resolve(context.Background(), &contracts.Request{}, "c")
	if fresh.Attempts[0].Provider != "a" {
		t.Fatalf("fresh process start = %v, want a (cursor resets)", providersOf(fresh))
	}
}

// TestWeightedRespectsProportion proves a seeded draw is proportional and
// deterministic.
func TestWeightedRespectsProportion(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	// a has weight 3, b weight 1; a should come first more often.
	steps := []combos.Step{
		{Kind: combos.StepModel, Ref: "m"},
	}
	_ = steps
	// The weight lives on the STEP; a single step with two providers cannot
	// differentiate weight per provider, so use two steps with different weights.
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyWeighted,
			combos.Step{Kind: combos.StepProviderWildcard, Ref: "a", Weight: 3},
			combos.Step{Kind: combos.StepProviderWildcard, Ref: "b", Weight: 1}),
	}}
	// Seed such that Intn(4) picks 3 (the 4th unit, inside b's... no: cumulative
	// is a=3 first, so r<3 picks a). A fixed r=0 always picks a.
	r := newTestResolver(t, cat, loader, WithRNG(fixedRNG{v: 0}))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Provider != "a" {
		t.Fatalf("weighted draw r=0 = %v, want a", providersOf(plan))
	}

	// With r=3 (the last unit of the 4), b is picked.
	r2 := newTestResolver(t, cat, loader, WithRNG(fixedRNG{v: 3}))
	plan2, err := r2.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan2.Attempts[0].Provider != "b" {
		t.Fatalf("weighted draw r=3 = %v, want b", providersOf(plan2))
	}

	// Deterministic with the same seed.
	r3 := newTestResolver(t, cat, loader, WithRNG(fixedRNG{v: 0}))
	plan3, _ := r3.Resolve(context.Background(), &contracts.Request{}, "c")
	if providersOf(plan3)[0] != providersOf(plan)[0] {
		t.Fatal("same seed produced a different draw")
	}
}

// TestP2CChoosesLowerPressure proves p2c picks the candidate with higher quota.
func TestP2CChoosesLowerPressure(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyP2C, modelStep("m", 0)),
	}}
	sig := newFakeSignals()
	sig.quota["a/m"] = 0.1 // high pressure
	sig.quota["b/m"] = 0.9 // low pressure
	// Intn with a fixed 0 picks a as the first of the pair; the pressure compare
	// then chooses b against a. To make the pair {a,b}, a stable order puts a
	// first, so the two draws yield indices 0 and 1.
	r := newTestResolver(t, cat, loader, WithRNG(fixedRNG{v: 0}), WithSignals(sig))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Provider != "b" {
		t.Fatalf("p2c order = %v, want b first (lower pressure)", providersOf(plan))
	}
}

// TestP2CWithoutRNGFallsBack proves a nil RNG yields the deterministic order.
func TestP2CWithoutRNGFallsBack(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyP2C, modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader) // no RNG
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Provider != "a" {
		t.Fatalf("p2c without RNG = %v, want stable order a first", providersOf(plan))
	}
}

// TestCostOrdersAscendingAndUnknownLast proves cost order and the unknown-last
// rule.
func TestCostOrdersAscendingAndUnknownLast(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "expensive", contracts.CapStream, 0).
		add("a", "cheap", contracts.CapStream, 0).
		add("a", "unknown", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyCost,
			modelStep("expensive", 0), modelStep("cheap", 0), modelStep("unknown", 0)),
	}}
	cost := fakeCost{m: map[string]int64{
		"a/expensive": 100, "a/cheap": 1, // unknown omitted
	}}
	r := newTestResolver(t, cat, loader, WithCost(cost))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 3 {
		t.Fatalf("attempts = %d", len(plan.Attempts))
	}
	if plan.Attempts[0].Model != "cheap" || plan.Attempts[1].Model != "expensive" || plan.Attempts[2].Model != "unknown" {
		t.Fatalf("cost order = %+v", plan.Attempts)
	}
}

// TestAutoWeightsSumToOneAndStable proves the auto weights sum to 1.0 and the
// order is deterministic.
func TestAutoWeightsSumToOneAndStable(t *testing.T) {
	sum := autoWeights.Quota + autoWeights.Health + autoWeights.Cost +
		autoWeights.Latency + autoWeights.Tier + autoWeights.CapFit
	if sum < 0.999999 || sum > 1.000001 {
		t.Fatalf("auto weights sum = %v, want 1.0", sum)
	}

	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyAuto, modelStep("m", 0)),
	}}
	sig := newFakeSignals()
	sig.quota["a/m"] = 0.2
	sig.quota["b/m"] = 0.9
	r := newTestResolver(t, cat, loader, WithSignals(sig))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Attempts[0].Provider != "b" {
		t.Fatalf("auto order = %v, want b (higher quota)", providersOf(plan))
	}
	// Determinism: same inputs, same order.
	plan2, _ := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if providersOf(plan2)[0] != "b" {
		t.Fatal("auto is not deterministic")
	}
}

// TestFillFirstExhaustsCurrentCredential proves a credential is pinned per
// provider and rotates on the cursor.
func TestFillFirstExhaustsCurrentCredential(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m", contracts.CapStream, 0).
		add("b", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFillFirst, modelStep("m", 0)),
	}}
	creds := fakeCreds{m: map[domain.ProviderID][]domain.CredentialID{
		"a": {"a-1", "a-2"}, "b": {"b-1"},
	}}
	r := newTestResolver(t, cat, loader, WithCredentials(creds))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Every candidate carries a concrete credential (account-aware).
	for _, c := range plan.Attempts {
		if c.Credential == "" {
			t.Fatalf("fill-first left a candidate without a credential: %+v", c)
		}
	}
	// The a-credential rotates on the next resolve.
	firstA := credentialOfProvider(plan, "a")
	plan2, _ := r.Resolve(context.Background(), &contracts.Request{}, "c")
	secondA := credentialOfProvider(plan2, "a")
	if firstA == secondA {
		t.Fatalf("fill-first did not rotate the a credential: %q then %q", firstA, secondA)
	}
}

// credentialOfProvider returns the credential of the first candidate with the
// provider.
func credentialOfProvider(plan contracts.RoutePlan, p domain.ProviderID) domain.CredentialID {
	for _, c := range plan.Attempts {
		if c.Provider == p {
			return c.Credential
		}
	}
	return ""
}

// TestDefaultStrategyIsAuto proves a combo with an unset strategy resolves with
// auto.
func TestDefaultStrategyIsAuto(t *testing.T) {
	cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", "", modelStep("m", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Strategy != contracts.StrategyAuto {
		t.Fatalf("strategy = %v, want auto", plan.Strategy)
	}
}
