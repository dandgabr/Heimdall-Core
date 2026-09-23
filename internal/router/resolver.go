package router

import (
	"context"
	"sort"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Resolver is the concrete contracts.Router (ADR-0009). It loads a combo,
// expands its steps into candidates, applies capability-aware ordering and
// orders them per the combo's strategy. It is pure over the catalogs it is given
// and holds only the in-memory cursor state (round-robin/fill-first).
type Resolver struct {
	combos      ComboLoader
	catalog     ModelCatalog
	registry    *registry
	registryErr error
	preflt      Preflight

	// Injected seams (all optional; nil uses a documented neutral default).
	rng    RNG
	cred   CredentialSource
	cost   CostCatalog
	signal Signals
	judge  Judge

	// mu guards the cursor: Resolve is safe for concurrent use; the rotation
	// state is shared across requests.
	mu     sync.Mutex
	cursor Cursor
}

var _ contracts.Router = (*Resolver)(nil)

// Option configures a Resolver.
type Option func(*Resolver)

// WithRNG injects the randomness source for weighted/p2c. Without it those
// strategies are non-deterministic by definition (ADR-0009 §4).
func WithRNG(r RNG) Option { return func(rr *Resolver) { rr.rng = r } }

// WithCredentials injects the credential source for fill-first / account
// round-robin.
func WithCredentials(c CredentialSource) Option { return func(rr *Resolver) { rr.cred = c } }

// WithCost injects the price catalog for cost/auto.
func WithCost(c CostCatalog) Option { return func(rr *Resolver) { rr.cost = c } }

// WithSignals injects the pressure telemetry for p2c/auto.
func WithSignals(s Signals) Option { return func(rr *Resolver) { rr.signal = s } }

// WithPreflight injects the preflight filter (quota + breaker, ADR-0009 §1.3).
// Without it no candidate is filtered.
func WithPreflight(p Preflight) Option { return func(rr *Resolver) { rr.preflt = p } }

// WithJudge injects the fusion judge port (ADR-0009 §3).
func WithJudge(j Judge) Option { return func(rr *Resolver) { rr.judge = j } }

// WithStrategies overrides the built-in strategy set (tests inject a subset or a
// fake). A nil entry or a duplicate is rejected.
func WithStrategies(list []Strategy) Option {
	return func(rr *Resolver) {
		reg, err := newRegistry(list)
		if err != nil {
			// A bad override is a programming error; surface it at Resolve by
			// leaving the registry nil, which Get treats as unavailable.
			rr.registry = nil
			rr.registryErr = err
			return
		}
		rr.registry = reg
	}
}

// New builds a Resolver over the combo loader and the model catalog. It returns
// an error only when the built-in strategy set is malformed (never in practice).
func New(loader ComboLoader, catalog ModelCatalog, opts ...Option) (*Resolver, error) {
	reg, err := newRegistry(defaultStrategyList())
	if err != nil {
		return nil, err
	}
	r := &Resolver{combos: loader, catalog: catalog, registry: reg}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// Resolve implements contracts.Router. combo selects a named combo; zero means
// automatic resolution (a single candidate from the request's own model).
func (r *Resolver) Resolve(ctx context.Context, req *contracts.Request, combo domain.ComboID) (contracts.RoutePlan, error) {
	if req == nil {
		return contracts.RoutePlan{}, invalidCombo("", "nil request")
	}
	if r.registryErr != nil {
		return contracts.RoutePlan{}, r.registryErr
	}

	// Automatic resolution (no combo): the request names its own model; search
	// every provider that declares it. The strategy is auto.
	if combo == "" {
		return r.resolveAuto(ctx, req)
	}

	c, err := r.combos.Get(ctx, combo)
	if err != nil {
		return contracts.RoutePlan{}, err
	}
	all, err := r.combos.List(ctx)
	if err != nil {
		return contracts.RoutePlan{}, err
	}
	byID := make(map[domain.ComboID]combos.Combo, len(all)+1)
	for _, other := range all {
		byID[other.ID] = other
	}
	byID[c.ID] = c

	kind := defaultStrategy(c.Strategy)
	strategy, err := r.registry.Get(kind)
	if err != nil {
		return contracts.RoutePlan{}, invalidCombo(c.Name, "unknown strategy "+string(kind))
	}

	expanded, err := r.expand(ctx, c, req, byID, 0, map[domain.ComboID]bool{})
	if err != nil {
		return contracts.RoutePlan{}, err
	}
	if len(expanded) == 0 {
		return contracts.RoutePlan{}, noCandidate()
	}

	// Preflight (quota + breaker) removes/demotes before ordering. It is a
	// filter, never a gate (ADR-0009 §1.3).
	expanded = r.preflight(ctx, expanded)

	order := r.orderEnvelope(ctx, strategy, kind, c.Name, req, expanded)
	if len(order) == 0 {
		return contracts.RoutePlan{}, noCandidate()
	}

	plan := contracts.RoutePlan{
		Combo:     c.ID,
		Strategy:  kind,
		Attempts:  order,
		MaxRounds: maxRoundsFor(kind, c, len(expanded)),
	}

	// The structural strategies (fusion/pipeline) additionally carry a plan
	// SHAPE the Dispatcher executes, not just an order (ADR-0009 §3/§6, D-02).
	switch kind {
	case contracts.StrategyFusion:
		// Validate the recursion guards (fan-out cap, judge not fusion, judge
		// not self) and POPULATE Panels/Judge so the Dispatcher can fan out and
		// judge. buildFusionPlans returns an error for a guard violation, so a
		// bad plan never reaches the Dispatcher.
		fp, ferr := r.buildFusionPlans(ctx, req, c.Name, groupByStep(order, expanded), r.judge)
		if ferr != nil {
			return contracts.RoutePlan{}, ferr
		}
		plan.Panels = fp.panels
		if fp.judge.Attempts != nil {
			jp := fp.judge
			plan.Judge = &jp
		}
	case contracts.StrategyPipeline:
		// Carry the ordered per-step plans so the Dispatcher chains N→N+1 and
		// returns only the LAST step's response (§6).
		plan.Chain = pipelineChain(groupByStep(order, expanded))
	}
	return plan, nil
}

// resolveAuto resolves a request that names its own model and no combo: every
// provider declaring that model becomes a candidate, ordered by `auto`.
func (r *Resolver) resolveAuto(ctx context.Context, req *contracts.Request) (contracts.RoutePlan, error) {
	if req.Model == "" {
		return contracts.RoutePlan{}, noCandidate()
	}
	var expanded []expanded
	step := combos.Step{Kind: combos.StepModel, Ref: string(req.Model)}
	for _, provider := range r.catalog.Providers() {
		caps, ok := r.catalog.Capabilities(provider, req.Model)
		if !ok {
			continue
		}
		mods, _ := r.catalog.Modalities(provider, req.Model)
		expanded = append(expanded, r.mkExpanded(req, 0, step, provider, req.Model, caps, mods))
	}
	if len(expanded) == 0 {
		return contracts.RoutePlan{}, noCandidate()
	}
	expanded = r.preflight(ctx, expanded)
	strategy, err := r.registry.Get(contracts.StrategyAuto)
	if err != nil {
		return contracts.RoutePlan{}, err
	}
	order := r.orderEnvelope(ctx, strategy, contracts.StrategyAuto, "", req, expanded)
	if len(order) == 0 {
		return contracts.RoutePlan{}, noCandidate()
	}
	return contracts.RoutePlan{
		Strategy:  contracts.StrategyAuto,
		Attempts:  order,
		MaxRounds: 1,
	}, nil
}

// orderEnvelope runs the strategy under the cursor lock (the stateful strategies
// mutate the cursor) and then applies the shared capability-aware demotion so an
// incompatible candidate is NEVER dropped, only moved to the end (ADR-0013 §3.7).
func (r *Resolver) orderEnvelope(ctx context.Context, strategy Strategy, kind contracts.StrategyKind, comboName string, req *contracts.Request, in []expanded) []contracts.Candidate {
	r.mu.Lock()
	order := strategy.Order(ctx, req, in, Env{
		Cursor:  &r.cursor,
		RNG:     r.rng,
		Combo:   comboName,
		Cred:    r.cred,
		Cost:    r.cost,
		Signals: r.signal,
	})
	r.mu.Unlock()
	return r.demote(order, in)
}

// demote moves incompatible candidates to the end, preserving the strategy
// order among compatible and among incompatible ones (a stable partition, never
// a drop). The compatibility comes from the expanded set, keyed by candidate.
func (r *Resolver) demote(order []contracts.Candidate, in []expanded) []contracts.Candidate {
	compat := make(map[string]bool, len(in))
	for _, e := range in {
		compat[stableKey(e.candidate)] = e.compatible
	}
	out := make([]contracts.Candidate, len(order))
	copy(out, order)
	sort.SliceStable(out, func(i, j int) bool {
		ci := compat[stableKey(out[i])]
		cj := compat[stableKey(out[j])]
		if ci != cj {
			return ci // compatible first
		}
		return false
	})
	return out
}

// preflight applies the injected Preflight to the expanded set, dropping
// candidates it rejects (with the reason folded into the Reason for audit).
func (r *Resolver) preflight(ctx context.Context, in []expanded) []expanded {
	if r.preflt == nil {
		return in
	}
	out := make([]expanded, 0, len(in))
	for _, e := range in {
		ok, reason := r.preflt.AllowCandidate(ctx, e.candidate)
		if !ok {
			// A preflight rejection is a FILTER (ADR-0009 §1.3): the candidate
			// does not enter the plan. The reason is not carried on the removed
			// candidate (it is not in the plan) but a plan that becomes empty is
			// a typed no_candidate error.
			_ = reason
			continue
		}
		out = append(out, e)
	}
	return out
}

// maxRoundsFor bounds the Dispatcher loop per strategy (ADR-0009 §1.4): never
// zero, never infinite.
func maxRoundsFor(kind contracts.StrategyKind, c combos.Combo, n int) int {
	switch kind {
	case contracts.StrategyFusion:
		// Fusion may re-enter once for the judge.
		return 2
	case contracts.StrategyPipeline:
		return len(c.Steps)
	default:
		if n < 1 {
			return 1
		}
		return n
	}
}
