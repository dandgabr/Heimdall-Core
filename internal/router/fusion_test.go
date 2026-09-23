package router

import (
	"context"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestFusionResolvesWithJudge proves a fusion combo resolves, builds one panel
// per candidate and validates the judge plan.
func TestFusionResolvesWithJudge(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	judge := fakeJudge{plan: contracts.RoutePlan{
		Combo:     "judge",
		Strategy:  contracts.StrategyAuto,
		MaxRounds: 1,
		Attempts:  []contracts.Candidate{{Provider: "a", Model: "judge-model"}},
	}}
	r := newTestResolver(t, cat, loader, WithJudge(judge))
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.Strategy != contracts.StrategyFusion {
		t.Fatalf("strategy = %v", plan.Strategy)
	}
	if len(plan.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 panels", len(plan.Attempts))
	}
	if plan.MaxRounds != 2 {
		t.Fatalf("MaxRounds = %d, want 2 (fusion may re-enter for the judge)", plan.MaxRounds)
	}
	// D-02: the plan now CARRIES the panels and the judge.
	if len(plan.Panels) != 2 {
		t.Fatalf("Panels = %d, want 2", len(plan.Panels))
	}
	if plan.Panels[0].Label != "panel-1" || plan.Panels[1].Label != "panel-2" {
		t.Fatalf("panel labels = %q / %q", plan.Panels[0].Label, plan.Panels[1].Label)
	}
	if plan.Judge == nil || len(plan.Judge.Attempts) != 1 {
		t.Fatalf("Judge not populated: %+v", plan.Judge)
	}
}

// TestFusionPlanCarriesPanelsWithoutJudge proves the degenerate no-judge case
// still carries the panels (Judge nil), which the Dispatcher treats as the
// first-successful-panel fallback.
func TestFusionPlanCarriesPanelsWithoutJudge(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	r := newTestResolver(t, cat, loader) // no judge
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Panels) != 2 {
		t.Fatalf("Panels = %d, want 2", len(plan.Panels))
	}
	if plan.Judge != nil {
		t.Fatalf("Judge = %+v, want nil without a judge port", plan.Judge)
	}
}

// TestFusionRefusesFusionJudge proves a judge whose plan is itself fusion is
// refused (infinite recursion, ADR-0009 §3).
func TestFusionRefusesFusionJudge(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	judge := fakeJudge{plan: contracts.RoutePlan{Strategy: contracts.StrategyFusion}}
	r := newTestResolver(t, cat, loader, WithJudge(judge))
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteFusionSelfJudge) {
		t.Fatalf("err = %v, want fusion_self_judge", err)
	}
}

// TestFusionRefusesSelfComboJudge proves a judge plan whose Combo is the fusion
// combo itself is refused.
func TestFusionRefusesSelfComboJudge(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	judge := fakeJudge{plan: contracts.RoutePlan{
		Combo:    "c", // the fusion combo itself
		Strategy: contracts.StrategyAuto,
	}}
	r := newTestResolver(t, cat, loader, WithJudge(judge))
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteFusionSelfJudge) {
		t.Fatalf("err = %v, want fusion_self_judge", err)
	}
}

// TestFusionJudgeErrorPropagates proves a judge error surfaces.
func TestFusionJudgeErrorPropagates(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	want := errors.New("judge down")
	r := newTestResolver(t, cat, loader, WithJudge(fakeJudge{err: want}))
	if _, err := r.Resolve(context.Background(), &contracts.Request{}, "c"); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

// TestFusionWithoutJudgeStillResolves proves a fusion combo with no judge port
// (wave-3 wiring absent) still emits the panels.
func TestFusionWithoutJudgeStillResolves(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "m1", contracts.CapStream, 0).
		add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, modelStep("m1", 0), modelStep("m2", 0)),
	}}
	r := newTestResolver(t, cat, loader) // no judge
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Attempts) != 2 {
		t.Fatalf("attempts = %d", len(plan.Attempts))
	}
}

// TestFusionFanoutCapRefused proves the runtime fan-out cap is enforced.
func TestFusionFanoutCapRefused(t *testing.T) {
	cat := newFakeCatalog()
	var steps []combos.Step
	for i := 0; i < maxFanout+1; i++ {
		m := domain.ModelID("m" + itoa(i))
		cat.add("a", m, contracts.CapStream, 0)
		steps = append(steps, modelStep(string(m), 0))
	}
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyFusion, steps...),
	}}
	r := newTestResolver(t, cat, loader)
	_, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if !hasCode(err, domain.CodeRouteFanoutExceeded) {
		t.Fatalf("err = %v, want fanout_exceeded", err)
	}
}

// TestPanelsFromGroups covers the panel builder: one panel per step group, with
// stable anonymised labels.
func TestPanelsFromGroups(t *testing.T) {
	if panelsFromGroups(nil) != nil {
		t.Fatal("nil input produced panels")
	}
	groups := [][]contracts.Candidate{
		{{Provider: "a", Model: "m"}},
		{{Provider: "b", Model: "n"}, {Provider: "c", Model: "n"}},
	}
	panels := panelsFromGroups(groups)
	if len(panels) != 2 {
		t.Fatalf("panels = %d, want 2", len(panels))
	}
	if panels[0].Label != "panel-1" || panels[1].Label != "panel-2" {
		t.Fatalf("labels = %q / %q", panels[0].Label, panels[1].Label)
	}
	if len(panels[1].Plan.Attempts) != 2 || panels[1].Plan.MaxRounds != 2 {
		t.Fatalf("panel1 = %+v", panels[1])
	}
	// An empty group is skipped without consuming a label.
	skipped := panelsFromGroups([][]contracts.Candidate{{}, {{Provider: "a", Model: "m"}}})
	if len(skipped) != 1 || skipped[0].Label != "panel-1" {
		t.Fatalf("empty group handling = %+v", skipped)
	}
}

// TestPipelineChainCoversEmptyGroups covers the empty-group skip and the
// empty-input guard.
func TestPipelineChainCoversEmptyGroups(t *testing.T) {
	if pipelineChain(nil) != nil {
		t.Fatal("nil groups produced a chain")
	}
	chain := pipelineChain([][]contracts.Candidate{{}, {{Provider: "a", Model: "m"}}})
	if len(chain) != 1 || chain[0].Attempts[0].Provider != "a" {
		t.Fatalf("chain = %+v, want the one non-empty step", chain)
	}
}

// TestGroupByStep proves the step partition is deterministic and ordered.
func TestGroupByStep(t *testing.T) {
	cat := newFakeCatalog().add("a", "m1", contracts.CapStream, 0).add("b", "m2", contracts.CapStream, 0)
	loader := &fakeComboLoader{}
	r := newTestResolver(t, cat, loader)
	_ = r
	// Hand-build an expanded set with known steps.
	in := []expanded{
		{candidate: contracts.Candidate{Provider: "a", Model: "m1"}, step: 1},
		{candidate: contracts.Candidate{Provider: "b", Model: "m2"}, step: 0},
	}
	ordered := []contracts.Candidate{{Provider: "b", Model: "m2"}, {Provider: "a", Model: "m1"}}
	groups := groupByStep(ordered, in)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	// Step 0 comes first regardless of `ordered`.
	if groups[0][0].Provider != "b" || groups[1][0].Provider != "a" {
		t.Fatalf("groups = %+v", groups)
	}
}

// TestFusionAllFailedErrorShape covers the fusion_all_failed error constructor
// (the panels' failure is signalled by the Dispatcher in wave 3; here we pin the
// typed error's code and params).
func TestFusionAllFailedErrorShape(t *testing.T) {
	err := fusionAllFailed(3)
	if !hasCode(err, domain.CodeRouteFusionAllFailed) {
		t.Fatalf("err = %v", err)
	}
	de := err.(*domain.DomainError)
	if de.Params["panels"] != "3" {
		t.Fatalf("params = %+v", de.Params)
	}
}

// TestPipelineChainsSequentially proves a pipeline plan is in strict step order
// and MaxRounds equals the step count.
func TestPipelineChainsSequentially(t *testing.T) {
	cat := newFakeCatalog().
		add("a", "s1", contracts.CapStream, 0).
		add("a", "s2", contracts.CapStream, 0).
		add("a", "s3", contracts.CapStream, 0)
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"c": combo("c", contracts.StrategyPipeline,
			modelStep("s1", 0), modelStep("s2", 0), modelStep("s3", 0)),
	}}
	r := newTestResolver(t, cat, loader)
	plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.MaxRounds != 3 {
		t.Fatalf("MaxRounds = %d, want 3 (one per step)", plan.MaxRounds)
	}
	got := []domain.ModelID{plan.Attempts[0].Model, plan.Attempts[1].Model, plan.Attempts[2].Model}
	if got[0] != "s1" || got[1] != "s2" || got[2] != "s3" {
		t.Fatalf("pipeline order = %v", got)
	}
	for _, c := range plan.Attempts {
		if c.Reason == "" {
			t.Fatalf("missing reason: %+v", c)
		}
	}
	// D-02: the plan CARRIES the ordered step chain.
	if len(plan.Chain) != 3 {
		t.Fatalf("Chain = %d, want 3", len(plan.Chain))
	}
	for i, step := range plan.Chain {
		if len(step.Attempts) != 1 || step.Attempts[0].Model != got[i] {
			t.Fatalf("chain[%d] = %+v", i, step)
		}
	}
}

// TestMaxRoundsNeverZero proves every strategy emits MaxRounds >= 1.
func TestMaxRoundsNeverZero(t *testing.T) {
	for _, kind := range contracts.Strategies() {
		if kind == contracts.StrategyFusion {
			continue // fusion's cap is asserted separately
		}
		cat := newFakeCatalog().add("a", "m", contracts.CapStream, 0)
		loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
			"c": combo("c", kind, modelStep("m", 0)),
		}}
		r := newTestResolver(t, cat, loader)
		plan, err := r.Resolve(context.Background(), &contracts.Request{}, "c")
		if err != nil {
			t.Fatalf("%s: Resolve: %v", kind, err)
		}
		if plan.MaxRounds < 1 {
			t.Fatalf("%s: MaxRounds = %d", kind, plan.MaxRounds)
		}
	}
}
