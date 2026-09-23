package router

import (
	"context"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// Strategy orders a combo's expanded candidates into the final Attempts order.
// It is PURE over its inputs except for the two stateful strategies
// (round-robin, fill-first) which mutate the injected Cursor, and the two
// stochastic ones (weighted, p2c) which draw from the injected RNG. It never
// drops a candidate: an incompatible one is demoted to the end (ADR-0013 §3.7).
type Strategy interface {
	// Kind is the strategy's identity; it must equal the combo policy's kind.
	Kind() contracts.StrategyKind
	// Order returns the candidates in attempt order with their Score/Reason set.
	// rng may be nil for a deterministic strategy, and is required (non-nil) for
	// weighted/p2c — a nil rng makes those non-deterministic by definition.
	Order(ctx context.Context, req *contracts.Request, in []expanded, ec Env) []contracts.Candidate
}

// Env is the execution environment a strategy reads: the in-memory cursor
// (round-robin/fill-first), the RNG (weighted/p2c) and the read-only catalogs
// (credentials, cost, telemetry). All are injected so the Router stays
// deterministic under test; a nil field means "unavailable" and the strategy
// uses a documented neutral fallback.
type Env struct {
	Cursor *Cursor
	RNG    RNG
	// Combo is the combo name, used as the round-robin cursor key.
	Combo string
	// Cred lists a provider's credentials (fill-first). Nil = no accounts known.
	Cred CredentialSource
	// Cost prices a model (cost/auto). Nil = prices unknown.
	Cost CostCatalog
	// Signals supplies pressure factors (p2c/auto). Nil = neutral.
	Signals Signals
}

// registry is the closed strategy set. It is built once and never mutated.
type registry struct {
	mu sync.RWMutex
	m  map[contracts.StrategyKind]Strategy
}

// newRegistry builds a registry with every built-in strategy, rejecting a nil
// or duplicate registration (a misconfigured strategy set must fail loudly).
func newRegistry(list []Strategy) (*registry, error) {
	r := &registry{m: make(map[contracts.StrategyKind]Strategy, len(list))}
	for _, s := range list {
		if s == nil {
			return nil, invalidCombo("", "nil strategy")
		}
		k := s.Kind()
		if _, ok := contracts.ParseStrategyKind(string(k)); !ok {
			return nil, invalidCombo("", "unknown strategy kind "+string(k))
		}
		if _, dup := r.m[k]; dup {
			return nil, invalidCombo("", "duplicate strategy "+string(k))
		}
		r.m[k] = s
	}
	return r, nil
}

// Get returns the strategy for kind, or route.invalid_combo when absent.
func (r *registry) Get(kind contracts.StrategyKind) (Strategy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.m[kind]
	if !ok {
		return nil, invalidCombo("", "unknown strategy "+string(kind))
	}
	return s, nil
}

// defaultStrategyList is a seam over the built-in strategy list, so a test can
// inject a malformed set and reach New's construction-error branch (which a
// healthy built-in list can never produce).
var defaultStrategyList = defaultStrategies

// defaultStrategies is the built-in set. The order is irrelevant (the map is
// keyed), but it is fixed for a deterministic construction error.
func defaultStrategies() []Strategy {
	return []Strategy{
		priorityStrategy{},
		fallbackStrategy{},
		roundRobinStrategy{},
		weightedStrategy{},
		fillFirstStrategy{},
		costStrategy{},
		p2cStrategy{},
		fusionStrategy{},
		pipelineStrategy{},
		autoStrategy{},
	}
}

// isTerminalKind reports whether a strategy kind is allowed to be a fusion
// judge (never fusion itself; ADR-0009 §3).
func isFusionKind(k contracts.StrategyKind) bool { return k == contracts.StrategyFusion }

// defaultStrategy returns the combo's strategy, or auto when it is zero/unset
// (ADR-0009 §2: auto is the default when a combo declares no policy).
func defaultStrategy(k contracts.StrategyKind) contracts.StrategyKind {
	if _, ok := contracts.ParseStrategyKind(string(k)); ok {
		return k
	}
	return contracts.StrategyAuto
}
