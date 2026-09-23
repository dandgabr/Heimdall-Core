package router

import (
	"context"
	"sort"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file holds the two STRUCTURAL strategies: fusion (fan-out + judge) and
// pipeline (sequential chaining). They do not produce a simple linear order;
// they need a runner (fusion) or a chaining rule (pipeline), so the Resolver
// handles them specially after the strategies_sequential.go ordering is applied
// to each stage.

// fusionPlan is the structural output of a fusion resolve: the panels (each a
// labelled mini RoutePlan) plus the judge plan. It is produced by the resolver,
// not by a Strategy.Order call, because fan-out is not a linear order.
type fusionPlan struct {
	panels []contracts.Panel
	judge  contracts.RoutePlan
}

// fusionStrategy marks the kind; its ordering is handled by the resolver which
// builds the panels (one per step/tier) and asks the Judge port.
type fusionStrategy struct{}

// Kind implements Strategy.
func (fusionStrategy) Kind() contracts.StrategyKind { return contracts.StrategyFusion }

// Order implements Strategy. For fusion the "order" is the panel order: each
// step/tier becomes one panel, ordered by step. The resolver builds the actual
// panel plans and the judge plan.
func (fusionStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, _ Env) []contracts.Candidate {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].step != in[j].step {
			return in[i].step < in[j].step
		}
		return lessStable(in[i].candidate, in[j].candidate)
	})
	out := make([]contracts.Candidate, 0, len(in))
	for i := range in {
		c := in[i].candidate
		c.Reason = buildReason(contracts.StrategyFusion, in[i], "")
		out = append(out, c)
	}
	return out
}

// pipelineStrategy marks the kind; its ordering is the declared step order, and
// the resolver marks the chain so the Dispatcher feeds step N's output into N+1.
type pipelineStrategy struct{}

// Kind implements Strategy.
func (pipelineStrategy) Kind() contracts.StrategyKind { return contracts.StrategyPipeline }

// Order implements Strategy: strict declared step order (never reordered).
func (pipelineStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, _ Env) []contracts.Candidate {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].step != in[j].step {
			return in[i].step < in[j].step
		}
		return lessStable(in[i].candidate, in[j].candidate)
	})
	out := make([]contracts.Candidate, 0, len(in))
	for i := range in {
		c := in[i].candidate
		c.Reason = buildReason(contracts.StrategyPipeline, in[i], "chain=sequential")
		out = append(out, c)
	}
	return out
}

// buildFusionPlans groups the ordered candidates into one panel per step and
// asks the Judge for the judge plan. It enforces the recursion guards:
//
//   - fan-out cap: len(panels) <= combos.MaxFanout (validated at save, re-checked
//     here because the Router never trusts persisted data blindly);
//   - the judge plan must not be a fusion plan whose FIRST candidate resolves to
//     the fusion combo itself (infinite recursion, ADR-0009 §3);
//   - the judge plan's strategy must not be fusion (a fusion judge would recurse).
//
// groups is the step-partitioned ordered candidates (see groupByStep): each group
// becomes ONE panel, so a step with several providers fans them out together.
func (r *Resolver) buildFusionPlans(ctx context.Context, req *contracts.Request, comboName string, groups [][]contracts.Candidate, judge Judge) (fusionPlan, error) {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total == 0 {
		return fusionPlan{}, noCandidate()
	}
	if len(groups) > maxFanout {
		return fusionPlan{}, fanoutExceeded(comboName, len(groups))
	}
	if judge == nil {
		// Without a judge port, fusion cannot resolve: the panels are still a
		// valid plan, but the judge is required by contract.
		return fusionPlan{
			panels: panelsFromGroups(groups),
		}, nil
	}

	panels := panelsFromGroups(groups)
	outputs := make([]string, 0, len(panels)) // empty at resolve time; the Dispatcher fills them
	jp, err := judge.JudgePlan(ctx, req, outputs)
	if err != nil {
		return fusionPlan{}, err
	}
	if isFusionKind(jp.Strategy) {
		return fusionPlan{}, fusionSelfJudge(comboName)
	}
	// Self-reference: the judge plan must not name the fusion combo itself
	// (running the judge would re-enter the same fusion and recurse forever).
	if string(jp.Combo) == comboName {
		return fusionPlan{}, fusionSelfJudge(comboName)
	}
	return fusionPlan{panels: panels, judge: jp}, nil
}

// panelsFromGroups turns the step-partitioned candidates into the fusion panels
// the Dispatcher runs (ADR-0009 §3). A panel is ONE branch: the candidates of a
// single step, so a step with several providers fans them out together. Each
// panel gets a stable ANONYMISED label ("panel-1", …) so the judge sees content,
// not vendor provenance.
func panelsFromGroups(groups [][]contracts.Candidate) []contracts.Panel {
	if len(groups) == 0 {
		return nil
	}
	panels := make([]contracts.Panel, 0, len(groups))
	for _, g := range groups {
		if len(g) == 0 {
			continue
		}
		panels = append(panels, contracts.Panel{
			Label: "panel-" + itoa(len(panels)+1),
			Plan: contracts.RoutePlan{
				Attempts:  append([]contracts.Candidate(nil), g...),
				MaxRounds: len(g),
			},
		})
	}
	return panels
}

// groupByStep partitions the ordered candidates by their ORIGINATING STEP,
// preserving both the step order (ascending) and the intra-step order the
// strategy produced. The step index is not carried on contracts.Candidate, so it
// is read from the expanded set (keyed by the stable candidate key). A candidate
// absent from `in` (which cannot happen for a plan built from the same resolve)
// falls into its own trailing group.
func groupByStep(ordered []contracts.Candidate, in []expanded) [][]contracts.Candidate {
	stepOf := make(map[string]int, len(in))
	for i := range in {
		stepOf[stableKey(in[i].candidate)] = in[i].step
	}
	// Deterministic step order: the distinct steps seen, ascending.
	var steps []int
	seen := map[int]bool{}
	for _, c := range ordered {
		s := stepOf[stableKey(c)]
		if !seen[s] {
			seen[s] = true
			steps = append(steps, s)
		}
	}
	sort.Ints(steps)

	groups := make([][]contracts.Candidate, 0, len(steps))
	for _, s := range steps {
		var g []contracts.Candidate
		for _, c := range ordered {
			if stepOf[stableKey(c)] == s {
				g = append(g, c)
			}
		}
		groups = append(groups, g)
	}
	return groups
}

// pipelineChain builds the ordered per-step plans the Dispatcher runs
// sequentially (ADR-0009 §6). Each step is one RoutePlan holding that step's
// candidates; only the LAST step's response reaches the client.
func pipelineChain(groups [][]contracts.Candidate) []contracts.RoutePlan {
	if len(groups) == 0 {
		return nil
	}
	chain := make([]contracts.RoutePlan, 0, len(groups))
	for _, g := range groups {
		if len(g) == 0 {
			continue
		}
		chain = append(chain, contracts.RoutePlan{
			Attempts:  append([]contracts.Candidate(nil), g...),
			MaxRounds: len(g),
		})
	}
	return chain
}

// fanoutExceeded builds a route.fanout_exceeded error (the combos package has
// its own for save time; the Router re-checks at resolve).
func fanoutExceeded(name string, n int) error {
	return domain.New(domain.CodeRouteFanoutExceeded,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "max": itoa(maxFanout)}),
	)
}

// maxFanout mirrors combos.MaxFanout so the runtime cap cannot diverge from the
// save-time cap (ADR-0013 §3.5).
const maxFanout = 8
