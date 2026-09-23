package contracts

import (
	"time"
)

// This file freezes the circuit-breaker contract of F3 (ADR-0012). The breaker
// is consulted in the PREFLIGHT (Allow) and updated by the Dispatcher
// (OnResult); it decides ONLY from the typed AttemptOutcome, never from a Code
// or an HTTP status (ADR-0002). Cota esgotada e falha de provider são estados
// SEPARADOS: uma credencial pode ter a janela gasta e o circuito fechado, ou o
// contrário.
//
// Anti-cycle rule (unchanged): this file imports only internal/domain and the
// standard library.

// BreakerScope is the granularity of a circuit. A ScopeProvider failure (5xx,
// network) opens Provider AND Model; a ScopeCredential failure (401/403, quota)
// opens only Credential (ADR-0012 §1).
type BreakerScope uint8

const (
	// BreakerProvider covers every candidate of one provider family.
	BreakerProvider BreakerScope = iota
	// BreakerCredential covers one account; other accounts of the family stay
	// available.
	BreakerCredential
	// BreakerModel covers one provider+model pair.
	BreakerModel
)

func (s BreakerScope) String() string {
	switch s {
	case BreakerProvider:
		return "provider"
	case BreakerCredential:
		return "credential"
	case BreakerModel:
		return "model"
	default:
		return "unknown"
	}
}

// BreakerKey is the circuit key derived from a Candidate and a scope. It is the
// stable identity of a circuit: for Provider only Provider is set; for
// Credential the account is set; for Model the model is set.
type BreakerKey struct {
	Scope      BreakerScope
	Provider   string
	Credential string
	Model      string
}

// KeyFor derives the breaker key of a candidate at the given scope.
func KeyFor(c Candidate, scope BreakerScope) BreakerKey {
	k := BreakerKey{Scope: scope, Provider: string(c.Provider)}
	switch scope {
	case BreakerCredential:
		k.Credential = string(c.Credential)
	case BreakerModel:
		k.Model = string(c.Model)
	}
	return k
}

// BreakerState is the state of one circuit. Terminal is ABSORVENTE: a terminal
// state (banned / credits_exhausted / expired) is never reopened by a transient
// cooldown nor by time; only an explicit action clears it (ADR-0012 §4).
type BreakerState uint8

const (
	// BreakerClosed is healthy.
	BreakerClosed BreakerState = iota
	// BreakerOpen is in cooldown until OpenUntil.
	BreakerOpen
	// BreakerHalfOpen is a probe window: exactly one request is allowed.
	BreakerHalfOpen
	// BreakerTerminal is invalid until human action.
	BreakerTerminal
)

func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	case BreakerTerminal:
		return "terminal"
	default:
		return "unknown"
	}
}

// Breaker is the circuit-breaker port. It is consulted in the preflight (Allow)
// and updated by the Dispatcher (OnResult). It decides only from typed fields.
//
// INVARIANTS (ADR-0012):
//   - ScopeRequest (AttemptOutcome == OutcomeClientError) NEVER records: a 400
//     must not cool down a healthy account. An implementation's OnResult is a
//     no-op for that outcome.
//   - Terminal states are absorventes: a transient OnResult does not reopen a
//     terminal circuit.
//   - RetryAfter (carried in Usage via the Dispatcher's classification) wins
//     over the exponential backoff.
type Breaker interface {
	// Allow reports whether a candidate may be attempted now, reserving the
	// half-open probe slot when the circuit just reopened (one probe at a time).
	Allow(c Candidate) bool
	// OnResult applies the result of ONE attempt. It is a no-op for a
	// client-scoped outcome (no Record, ADR-0012 §2). It is the only mutator.
	OnResult(c Candidate, outcome AttemptOutcome, u Usage)
	// RetryAfter reports the remaining cooldown of a candidate's circuit; zero
	// means "not open" (may be attempted now).
	RetryAfter(c Candidate) time.Duration
}
