// Package router implements the Router of F3 (ADR-0009): it turns a request
// into an ORDERED RoutePlan of Candidates. It never calls an upstream, opens a
// credential or persists.
//
// # Position
//
// The Router is a pure decision layer over the frozen contracts
// (internal/contracts/router.go) and the combo data (internal/combos). It loads
// a combo, expands its steps into Candidates (concrete model, nested combo-ref
// with a depth cap, provider wildcard), applies capability-aware ordering
// (reorder, never drop) and orders per the combo's strategy.
//
// # Determinism
//
// Every strategy is deterministic for the same input, state and seed (ADR-0009
// §4). The two stochastic strategies (`weighted`, `p2c`) take an injectable
// `RNG`; without one they are non-deterministic BY DEFINITION (documented, not a
// bug). All ties are broken by the stable (Provider, Model, Credential) key.
//
// # State
//
// `round-robin` and `fill-first` carry IN-MEMORY state (a cursor / a current
// credential pointer) that is NOT persisted: a restart resets it (ADR-0009 §4,
// ADR-0013 §5). The combo is the policy (declaration); the cursor is execution.
package router

import (
	"context"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ComboLoader reads the combo named by id, or combos.ErrNotFound. The
// ComboStore (internal/store) satisfies it; keeping it an interface keeps the
// Router testable without SQLite.
type ComboLoader interface {
	Get(ctx context.Context, id domain.ComboID) (combos.Combo, error)
	// List returns every combo; the Router uses it to resolve nested combo-refs.
	List(ctx context.Context) ([]combos.Combo, error)
}

// ModelCatalog reports a provider's declared models and their capabilities. The
// provider registry (internal/providers) satisfies it via the families; keeping
// it an interface is what lets the Router expand a wildcard and compute the
// capability fit without importing the concrete registry.
type ModelCatalog interface {
	// Providers returns the known provider IDs in deterministic order.
	Providers() []domain.ProviderID
	// Models returns a provider's declared models in deterministic order.
	Models(provider domain.ProviderID) []domain.ModelID
	// Capabilities reports a model's declared capabilities; ok=false when the
	// family does not know the model.
	Capabilities(provider domain.ProviderID, model domain.ModelID) (contracts.Capabilities, bool)
	// Modalities reports a model's declared modalities; ok=false when unknown.
	Modalities(provider domain.ProviderID, model domain.ModelID) (contracts.ModalitySet, bool)
}

// Preflight filters/demotes candidates before the plan is emitted (ADR-0009
// §1.3). The concrete `QuotaFilter` and `Breaker` checks the Dispatcher runs
// live here as a composed port; the Router calls it once per candidate. A nil
// preflight means "no filtering" (documented as the test/compat default).
type Preflight interface {
	// AllowCandidate reports whether a candidate survives preflight, with a
	// reason for the audit when it does not.
	AllowCandidate(ctx context.Context, c contracts.Candidate) (bool, string)
}

// PanelRunner runs ONE fusion panel (a mini-plan) and returns its textual
// response for the judge. It is the injected port for `fusion`: the concrete
// Dispatcher lands in a later wave, so the Router only knows this narrow shape.
type PanelRunner interface {
	// RunPanel executes one panel and returns its response text. An error means
	// the panel failed; a partial-success fan-out tolerates some failures.
	RunPanel(ctx context.Context, panel contracts.RoutePlan) (string, error)
}

// Judge decides/synthesises across panel outputs. It is injected alongside the
// PanelRunner so the fusion plan can be resolved without the Router knowing the
// judge's model: JudgePlan names the judge candidate, and the Router refuses a
// judge that resolves to the fusion combo itself (infinite recursion).
type Judge interface {
	// JudgePlan returns the plan that runs the judge. It must not be the fusion
	// combo (ADR-0009 §3): the Router validates that.
	JudgePlan(ctx context.Context, req *contracts.Request, outputs []string) (contracts.RoutePlan, error)
}

// RNG is the injectable randomness source for `weighted` and `p2c`. It is
// deliberately tiny so a test can supply a fixed sequence; a `*rand.Rand`
// adapter (RandSource) is provided. A nil RNG makes those strategies
// non-deterministic (the documented default).
type RNG interface {
	// Intn returns a pseudo-random int in [0, n). n > 0.
	Intn(n int) int
	// Float64 returns a pseudo-random float64 in [0.0, 1.0).
	Float64() float64
}

// Cursor is the in-memory rotation state for `round-robin` and `fill-first`. It
// is keyed by (combo, tier) and is NOT persisted (ADR-0009 §4): a restart resets
// it. The zero value is ready to use.
type Cursor struct {
	// roundRobin is the rotating index per (combo, tier) key.
	roundRobin map[string]int
	// fillFirst is the current credential index per provider key.
	fillFirst map[string]int
}

// CredentialSource lists the known credentials of a provider, in deterministic
// order. The Router uses it for the account-aware strategies (fill-first,
// account round-robin); the store's CredentialStore satisfies it.
type CredentialSource interface {
	Credentials(provider domain.ProviderID) []domain.CredentialID
}

// CostCatalog reports the estimated cost of a model, in micro-units per token.
// ok=false means the price is unknown, and `cost` sends that candidate to the
// end (ADR-0009 §2).
type CostCatalog interface {
	CostMicros(provider domain.ProviderID, model domain.ModelID) (int64, bool)
}

// Signals supplies the normalized pressure factors the `p2c` and `auto`
// strategies read. Every method is a read: it never mutates state and never
// calls an upstream. A nil Signals means "no telemetry": the factors default to
// neutral values (quota 1.0, health 1.0, latency 0.0, in-flight 0).
type Signals interface {
	// QuotaRemaining is the fraction of quota left for a candidate's credential
	// in [0,1]; 1.0 when unknown (fail-open, ADR-0011 §2.4).
	QuotaRemaining(ctx context.Context, c contracts.Candidate) float64
	// BreakerHealth is 1.0 for a closed circuit and 0.0 for an open/terminal one.
	BreakerHealth(ctx context.Context, c contracts.Candidate) float64
	// Latency is a normalized [0,1] latency where 0.0 is best; 0.0 when unknown.
	Latency(ctx context.Context, c contracts.Candidate) float64
	// InFlight is the number of concurrent attempts for the candidate's key.
	InFlight(ctx context.Context, c contracts.Candidate) int
}
