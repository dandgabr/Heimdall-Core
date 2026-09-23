package combos

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeProviders is a controllable ProviderSet for validation tests.
type fakeProviders struct {
	known  map[domain.ProviderID]bool
	models map[domain.ModelID]bool
}

func (f fakeProviders) Has(id domain.ProviderID) bool       { return f.known[id] }
func (f fakeProviders) DeclaresModel(m domain.ModelID) bool { return f.models[m] }

func providersFor(ids ...domain.ProviderID) fakeProviders {
	known := map[domain.ProviderID]bool{}
	for _, id := range ids {
		known[id] = true
	}
	return fakeProviders{known: known, models: map[domain.ModelID]bool{}}
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	de, ok := err.(*domain.DomainError)
	if !ok {
		t.Fatalf("err = %v (%T), want *domain.DomainError", err, err)
	}
	if de.Code != want {
		t.Fatalf("code = %q, want %q", de.Code, want)
	}
	if de.Scope != domain.ScopeRequest {
		t.Errorf("scope = %v, want request (an invalid combo must not cooldown)", de.Scope)
	}
}

func TestIsValidName(t *testing.T) {
	valid := []string{"a", "A1", "my.combo", "my_combo", "my-combo", "a.b-c_d"}
	for _, n := range valid {
		if !IsValidName(n) {
			t.Errorf("IsValidName(%q) = false, want true", n)
		}
	}
	invalid := []string{"", "has space", "slash/name", "hash#", "colon:name", "emoji😀", "new\nline"}
	for _, n := range invalid {
		if IsValidName(n) {
			t.Errorf("IsValidName(%q) = true, want false", n)
		}
	}
}

func TestComboValidateShape(t *testing.T) {
	ok := NewCombo("good", contracts.StrategyFallback, []Step{{Kind: StepModel, Ref: "m"}})
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid combo rejected: %v", err)
	}

	badName := ok
	badName.Name = "bad name"
	assertCode(t, badName.Validate(), domain.CodeRouteInvalidCombo)

	badStrategy := ok
	badStrategy.Strategy = "not-a-strategy"
	assertCode(t, badStrategy.Validate(), domain.CodeRouteInvalidCombo)

	noSteps := ok
	noSteps.Steps = nil
	assertCode(t, noSteps.Validate(), domain.CodeRouteInvalidCombo)

	badKind := ok
	badKind.Steps = []Step{{Kind: "bogus", Ref: "m"}}
	assertCode(t, badKind.Validate(), domain.CodeRouteInvalidCombo)

	emptyRef := ok
	emptyRef.Steps = []Step{{Kind: StepModel, Ref: ""}}
	assertCode(t, emptyRef.Validate(), domain.CodeRouteInvalidCombo)
}

func TestStepWeightOrOne(t *testing.T) {
	cases := map[int]int{0: 1, -5: 1, 1: 1, 7: 7}
	for in, want := range cases {
		if got := (Step{Weight: in}).WeightOrOne(); got != want {
			t.Errorf("WeightOrOne(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestStepKindIsKnown(t *testing.T) {
	for _, k := range allStepKinds {
		if !k.IsKnown() {
			t.Errorf("%q.IsKnown() = false", k)
		}
	}
	if StepKind("nope").IsKnown() {
		t.Error("unknown kind reported known")
	}
}

func TestValidateGraphDepthAndRefs(t *testing.T) {
	providers := providersFor("z.ai")
	existing := map[domain.ComboID]Combo{
		"leaf": NewCombo("leaf", contracts.StrategyFallback, []Step{{Kind: StepProviderWildcard, Ref: "z.ai"}}),
	}
	// A combo referencing the leaf has depth 1.
	parent := NewCombo("parent", contracts.StrategyPipeline, []Step{{Kind: StepComboRef, Ref: "leaf"}})
	depth, err := ValidateGraph(parent, existing, providers)
	if err != nil {
		t.Fatalf("ValidateGraph: %v", err)
	}
	if depth != 1 {
		t.Fatalf("depth = %d, want 1", depth)
	}

	// A reference to a missing combo is invalid.
	missing := NewCombo("bad", contracts.StrategyFallback, []Step{{Kind: StepComboRef, Ref: "ghost"}})
	assertCode(t, mustErr(ValidateGraph(missing, existing, providers)), domain.CodeRouteInvalidCombo)
}

func TestValidateGraphSelfCycle(t *testing.T) {
	self := NewCombo("self", contracts.StrategyFallback, []Step{{Kind: StepComboRef, Ref: "self"}})
	assertCode(t, mustErr(ValidateGraph(self, nil, providersFor())), domain.CodeRouteCyclicCombo)
}

func TestValidateGraphIndirectCycle(t *testing.T) {
	// a -> b, b -> a. Validating b with a already existing must detect the cycle.
	a := NewCombo("a", contracts.StrategyFallback, []Step{{Kind: StepComboRef, Ref: "b"}})
	b := NewCombo("b", contracts.StrategyFallback, []Step{{Kind: StepComboRef, Ref: "a"}})
	// Save a first (referencing b, which does not exist yet): refused.
	assertCode(t, mustErr(ValidateGraph(a, nil, providersFor())), domain.CodeRouteInvalidCombo)
	// With b pre-existing as a->... we make b's reference loop back.
	existing := map[domain.ComboID]Combo{"a": a}
	assertCode(t, mustErr(ValidateGraph(b, existing, providersFor())), domain.CodeRouteCyclicCombo)
}

func TestValidateGraphDepthCap(t *testing.T) {
	// Build a chain longer than MaxDepth and assert the innermost save is
	// refused. We add combos one by one so each is a create.
	existing := map[domain.ComboID]Combo{}
	var last Combo
	for i := 0; i <= MaxDepth; i++ {
		name := "c" + itoa(i)
		steps := []Step{{Kind: StepModel, Ref: "m"}}
		if i > 0 {
			steps = []Step{{Kind: StepComboRef, Ref: last.Name}}
		}
		c := NewCombo(name, contracts.StrategyPipeline, steps)
		// The allowlist lets the model step through.
		providers := fakeProviders{known: map[domain.ProviderID]bool{}, models: map[domain.ModelID]bool{"m": true}}
		depth, err := ValidateGraph(c, existing, providers)
		if i < MaxDepth {
			if err != nil {
				t.Fatalf("chain %d rejected early: %v", i, err)
			}
			c.Depth = depth
			existing[c.ID] = c
			last = c
			continue
		}
		// i == MaxDepth: the chain is MaxDepth deep, which is the cap, so it is
		// allowed. One more would exceed it. Assert the boundary is inclusive.
		if err != nil {
			t.Fatalf("chain at cap rejected: %v", err)
		}
		if depth != MaxDepth {
			t.Fatalf("depth = %d, want %d", depth, MaxDepth)
		}
	}
}

func TestValidateGraphDepthExceeded(t *testing.T) {
	// A single combo that references a pre-existing chain deeper than the cap.
	existing := map[domain.ComboID]Combo{}
	providers := fakeProviders{known: map[domain.ProviderID]bool{}, models: map[domain.ModelID]bool{"m": true}}
	prev := ""
	for i := 0; i <= MaxDepth; i++ {
		name := "d" + itoa(i)
		steps := []Step{{Kind: StepModel, Ref: "m"}}
		if prev != "" {
			steps = []Step{{Kind: StepComboRef, Ref: prev}}
		}
		c := NewCombo(name, contracts.StrategyPipeline, steps)
		depth, err := ValidateGraph(c, existing, providers)
		if err != nil {
			t.Fatalf("setup %d: %v", i, err)
		}
		c.Depth = depth
		existing[c.ID] = c
		prev = name
	}
	// Now a new combo on top exceeds.
	top := NewCombo("top", contracts.StrategyPipeline, []Step{{Kind: StepComboRef, Ref: prev}})
	assertCode(t, mustErr(ValidateGraph(top, existing, providers)), domain.CodeRouteDepthExceeded)
}

func TestValidateGraphProviderAllowlist(t *testing.T) {
	providers := providersFor("z.ai")
	// Unknown provider wildcard.
	badWildcard := NewCombo("w", contracts.StrategyFallback, []Step{{Kind: StepProviderWildcard, Ref: "ghost"}})
	assertCode(t, mustErr(ValidateGraph(badWildcard, nil, providers)), domain.CodeRouteUnknownProvider)

	// Unknown model (DeclaresModel false).
	badModel := NewCombo("m", contracts.StrategyFallback, []Step{{Kind: StepModel, Ref: "ghost"}})
	assertCode(t, mustErr(ValidateGraph(badModel, nil, providers)), domain.CodeRouteUnknownProvider)

	// Known provider wildcard is fine.
	goodWildcard := NewCombo("w", contracts.StrategyFallback, []Step{{Kind: StepProviderWildcard, Ref: "z.ai"}})
	if _, err := ValidateGraph(goodWildcard, nil, providers); err != nil {
		t.Fatalf("known wildcard rejected: %v", err)
	}

	// Nil provider set skips the allowlist (explicit opt-out).
	if _, err := ValidateGraph(badWildcard, nil, nil); err != nil {
		t.Fatalf("nil provider set should skip allowlist: %v", err)
	}
}

func TestValidateGraphFusionFanout(t *testing.T) {
	providers := fakeProviders{known: map[domain.ProviderID]bool{}, models: map[domain.ModelID]bool{"m": true}}
	steps := make([]Step, MaxFanout+1)
	for i := range steps {
		steps[i] = Step{Kind: StepModel, Ref: "m"}
	}
	fusion := NewCombo("f", contracts.StrategyFusion, steps)
	assertCode(t, mustErr(ValidateGraph(fusion, nil, providers)), domain.CodeRouteFanoutExceeded)

	// A non-fusion strategy with the same step count is fine (fan-out only
	// applies to fusion, which runs steps in parallel).
	fallback := NewCombo("f", contracts.StrategyFallback, steps)
	if _, err := ValidateGraph(fallback, nil, providers); err != nil {
		t.Fatalf("non-fusion fanout rejected: %v", err)
	}

	// Fusion at exactly the cap is allowed.
	atCap := NewCombo("f", contracts.StrategyFusion, steps[:MaxFanout])
	if _, err := ValidateGraph(atCap, nil, providers); err != nil {
		t.Fatalf("fusion at cap rejected: %v", err)
	}
}

func mustErr(_ int, err error) error { return err }

// TestValidateGraphShapeErrorPropagates covers the early return when the combo
// fails shape validation before graph validation runs.
func TestValidateGraphShapeErrorPropagates(t *testing.T) {
	bad := NewCombo("bad name", contracts.StrategyFallback, []Step{{Kind: StepModel, Ref: "m"}})
	assertCode(t, mustErr(ValidateGraph(bad, nil, providersFor())), domain.CodeRouteInvalidCombo)
}

// TestValidateGraphDiamondRevisitsNode covers the black-node reuse branch: a
// diamond (a->b, a->c, b->d, c->d) makes d visited twice, the second time as an
// already-black node.
func TestValidateGraphDiamondRevisitsNode(t *testing.T) {
	providers := fakeProviders{models: map[domain.ModelID]bool{"m": true}}
	existing := map[domain.ComboID]Combo{
		"b": NewCombo("b", contracts.StrategyPipeline, []Step{{Kind: StepComboRef, Ref: "d"}}),
		"c": NewCombo("c", contracts.StrategyPipeline, []Step{{Kind: StepComboRef, Ref: "d"}}),
		"d": NewCombo("d", contracts.StrategyPipeline, []Step{{Kind: StepModel, Ref: "m"}}),
	}
	a := NewCombo("a", contracts.StrategyPipeline, []Step{
		{Kind: StepComboRef, Ref: "b"},
		{Kind: StepComboRef, Ref: "c"},
	})
	depth, err := ValidateGraph(a, existing, providers)
	if err != nil {
		t.Fatalf("diamond rejected: %v", err)
	}
	if depth != 2 {
		t.Fatalf("depth = %d, want 2", depth)
	}
}

// TestValidateGraphExistingWithDanglingRef covers the guard for a malformed
// `existing` set (a stored combo that references a missing combo).
func TestValidateGraphExistingWithDanglingRef(t *testing.T) {
	providers := fakeProviders{models: map[domain.ModelID]bool{"m": true}}
	existing := map[domain.ComboID]Combo{
		"dangling": NewCombo("dangling", contracts.StrategyPipeline, []Step{{Kind: StepComboRef, Ref: "ghost"}}),
	}
	a := NewCombo("a", contracts.StrategyPipeline, []Step{
		{Kind: StepComboRef, Ref: "dangling"},
		{Kind: StepModel, Ref: "m"},
	})
	assertCode(t, mustErr(ValidateGraph(a, existing, providers)), domain.CodeRouteInvalidCombo)
}
