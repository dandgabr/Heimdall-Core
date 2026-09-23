package contracts

import (
	"context"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the Router contract of F3 (ADR-0009). The Router transforms
// a request into an ORDERED RoutePlan of Candidates; it does not execute (the
// Dispatcher, ADR-0010, does), does not open a credential and does not persist.
//
// Anti-cycle rule (unchanged): this package imports only internal/domain and the
// standard library.

// StrategyKind names one routing strategy. It is a string enum so a persisted
// combo (ADR-0013) stays readable and a new strategy can be added without
// renumbering. The zero value is the empty string, which ParseStrategyKind
// rejects: an unset strategy is a mistake, not "auto".
type StrategyKind string

const (
	StrategyPriority   StrategyKind = "priority"
	StrategyFallback   StrategyKind = "fallback"
	StrategyRoundRobin StrategyKind = "round-robin"
	StrategyWeighted   StrategyKind = "weighted"
	StrategyFillFirst  StrategyKind = "fill-first"
	StrategyCost       StrategyKind = "cost"
	StrategyP2C        StrategyKind = "p2c"
	StrategyFusion     StrategyKind = "fusion"
	StrategyPipeline   StrategyKind = "pipeline"
	StrategyAuto       StrategyKind = "auto"
)

// allStrategies is the ordered, closed set of strategies. It is the single
// source of truth for String/Parse and for any future enumeration.
var allStrategies = []StrategyKind{
	StrategyPriority, StrategyFallback, StrategyRoundRobin, StrategyWeighted,
	StrategyFillFirst, StrategyCost, StrategyP2C, StrategyFusion,
	StrategyPipeline, StrategyAuto,
}

// String returns the strategy name, or "" for an unknown value (never a
// fabricated name).
func (s StrategyKind) String() string {
	for _, k := range allStrategies {
		if k == s {
			return string(k)
		}
	}
	return ""
}

// ParseStrategyKind is the inverse of String. ok is false for anything outside
// the closed set, so a caller fails closed instead of defaulting to a strategy
// that changes routing behaviour.
func ParseStrategyKind(s string) (StrategyKind, bool) {
	for _, k := range allStrategies {
		if string(k) == s {
			return k, true
		}
	}
	return "", false
}

// Strategies returns every known strategy in a fixed order. It is a copy, so a
// caller cannot mutate the package's set.
func Strategies() []StrategyKind {
	out := make([]StrategyKind, len(allStrategies))
	copy(out, allStrategies)
	return out
}

// Request is the canonical, summarized request the Router needs to resolve a
// route. It is deliberately NOT the full WireRequest: routing cares about the
// target (model/combo), the required modality/capabilities (capability-aware
// ordering, ADR-0013 §3.7) and correlation — never the message body.
type Request struct {
	// ID correlates the request through logs/audit.
	ID domain.RequestID
	// Model is the requested model; zero when the request targets a Combo.
	Model domain.ModelID
	// Combo selects a named combo; zero means automatic resolution.
	Combo domain.ComboID
	// Modalities is the set of content modalities the request requires (e.g.
	// image input). The Router uses it for capability-aware ordering; an
	// incompatible candidate is demoted, never dropped (ADR-0013 §3.7).
	Modalities ModalitySet
	// Capabilities is the required protocol feature set. Same rule: demote, do
	// not drop.
	Capabilities Capabilities
	// Headers are request headers for routing-relevant hints. They are already
	// free of credentials (the Executor injects auth), so a header here can
	// never carry a token.
	Headers http.Header
}

// Candidate is ONE possible attempt: family, model and (when the strategy is
// account-aware) the concrete credential. Score is the value the strategy used
// to order it; Reason is observability — why this candidate, in this position.
// Reason is never an instruction (it is logged, shown in the GUI, and audited).
type Candidate struct {
	Provider domain.ProviderID
	Model    domain.ModelID
	// Credential zero means "any healthy credential of the family"; the
	// Dispatcher (ADR-0010) chooses. It is set when the strategy is
	// account-aware (fill-first, account round-robin).
	Credential domain.CredentialID
	Score      float64
	Reason     string
}

// Panel is ONE fusion fan-out branch (ADR-0009 §3). Label is the ANONYMISED
// identifier the judge sees ("panel-1", "panel-2", …) instead of the branch's
// provider/model provenance, so the judge synthesises on content and not on
// vendor. Plan is the mini-plan the Dispatcher runs for this branch.
//
// ADDITIVE (F3 correction D-02): the field is new; an existing consumer that
// only reads Attempts/MaxRounds/Strategy is unaffected.
type Panel struct {
	Label string
	Plan  RoutePlan
}

// RoutePlan is the Router's output. Attempts is ordered: the Dispatcher tries
// them in order. MaxRounds bounds the Dispatcher's loop (fusion/pipeline/deep
// failover) so a plan can never retry forever; it is always finite and >= 1.
//
// INVARIANTS (ADR-0009 §1):
//  1. Attempts is never empty with a nil error: an empty plan is a typed error
//     (route.no_candidate), never "success with nothing to do".
//  2. Attempts is deterministic for the same input, state and seed.
//  3. Attempts has already passed the preflight (QuotaFilter + Breaker): a
//     candidate with exhausted quota or an open circuit does not enter, or
//     enters demoted.
//  4. MaxRounds >= 1 and finite.
//
// STRUCTURAL PLANS (ADR-0009 §3/§6, F3 correction D-02):
//
//   - StrategyFusion: Panels is non-empty (one Panel per fan-out branch) and
//     Judge is the judge's route (nil when no judge route was resolvable, a
//     documented degenerate fallback). The Dispatcher runs every Panel in
//     parallel, feeds their ANONYMISED outputs to the judge request, and returns
//     the judge's result. The judge is a NORMAL request: it re-enters the
//     Dispatcher, so its reentrancy is bounded by the already-validated
//     MaxRounds/depth and it can never itself be a fusion plan (validated in the
//     Router, ADR-0009 §3).
//   - StrategyPipeline: Chain is the ordered list of step plans; the Dispatcher
//     runs them SEQUENTIALLY, feeding step N's output into step N+1's request,
//     and only the LAST step's response is returned to the caller.
//
// These fields are ADDITIVE: a plan for a linear strategy leaves them nil and
// every existing consumer keeps working unchanged.
type RoutePlan struct {
	Combo    domain.ComboID
	Attempts []Candidate
	// MaxRounds bounds the Dispatcher loop; >= 1.
	MaxRounds int
	// Strategy records which strategy produced the plan, so the Dispatcher and
	// the audit know how to interpret the order (ADR-0009 §1).
	Strategy StrategyKind
	// Panels is the fusion fan-out (StrategyFusion). Empty for other strategies.
	Panels []Panel
	// Judge is the fusion judge's route (StrategyFusion). nil means no judge
	// route was available; the Dispatcher then returns the first successful
	// panel (documented degenerate fallback).
	Judge *RoutePlan
	// Chain is the pipeline's ordered step plans (StrategyPipeline). Empty for
	// other strategies. Only the LAST step's response is returned.
	Chain []RoutePlan
}

// Router resolves a request into a RoutePlan. It is the ONLY component that
// decides "who and in what order"; it never calls an upstream, opens a
// credential or persists (ADR-0009 §1).
type Router interface {
	// Resolve returns an ordered plan for req. combo selects a named combo
	// (zero for automatic resolution). A plan with no candidate is a typed
	// error (route.no_candidate, ScopeRequest, Retryable=false): the request is
	// not serviceable and must not cooldown a credential.
	Resolve(ctx context.Context, req *Request, combo domain.ComboID) (RoutePlan, error)
}
