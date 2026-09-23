package contracts

import (
	"context"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the Dispatcher contract of F3 (ADR-0010). The Dispatcher is
// the OWNER of the attempt loop, the failover and the accounting: it receives a
// RoutePlan already resolved by the Router and talks to the Executor. It is NOT
// a Gate and NOT an HTTP handler.
//
// Anti-cycle rule (unchanged): this file imports only internal/domain and the
// standard library.

// AttemptOutcome classifies the result of ONE attempt. It mirrors the four
// DomainError scopes plus the success case; the Dispatcher derives it from the
// typed Scope/Retryable of the DomainError, never from the Code or HTTPStatus
// (ADR-0002 §"regras de classificação").
type AttemptOutcome uint8

const (
	// OutcomeSuccess: the attempt produced a response.
	OutcomeSuccess AttemptOutcome = iota
	// OutcomeClientError: ScopeRequest. TERMINAL and non-retryable: the loop
	// returns immediately and does NOT Record. Retrying a client error burns
	// quota and is the regression ADR-0002 exists to prevent.
	OutcomeClientError
	// OutcomeCredentialError: ScopeCredential (401/403 for the account, or
	// quota/429). The credential is the failure domain; the next candidate is
	// tried with cooldown = RetryAfter when present.
	OutcomeCredentialError
	// OutcomeProviderError: ScopeProvider (5xx/408/502/503/504, network/DNS/TLS).
	// The provider (and model) is the failure domain; exponential cooldown.
	OutcomeProviderError
	// OutcomeTransient: a retryable failure that does not map to a specific
	// scope (e.g. a cancelled attempt during a cooldown wait). It never coerces
	// a scope; the aggregate error keeps the last attempt's classification.
	OutcomeTransient
)

func (o AttemptOutcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeClientError:
		return "client_error"
	case OutcomeCredentialError:
		return "credential_error"
	case OutcomeProviderError:
		return "provider_error"
	case OutcomeTransient:
		return "transient"
	default:
		return "unknown"
	}
}

// IsTerminal reports whether the outcome stops the attempt loop immediately.
// Only a client error is terminal: it is the request's fault, so trying another
// credential cannot help and would waste quota (ADR-0010 §2.1).
func (o AttemptOutcome) IsTerminal() bool { return o == OutcomeClientError }

// Usage is the accounting of ONE attempt (never one request): a failover that
// burns two accounts emits two Usages, and N attempts consume N usages. It is
// what the UsageRecorder (ADR-0011) persists.
//
// Usage carries only the QUANTITIES and the identity of the attempt; the
// attempt's classification travels as the explicit `outcome` parameter of
// UsageRecorder.Record (see quota.go). Keeping the two separate means the same
// quantities can be recorded under a corrected outcome (e.g. a stream that is
// later known to have aborted) without reconstructing the numbers.
type Usage struct {
	// AttemptKey is the deterministic idempotency key,
	// "{request_id}:{candidate}:{seq}" (ADR-0011 §4). It is what makes the
	// recorder idempotent: a re-delivery (or a partial/aborted stream replacing
	// a full one) never double-counts.
	AttemptKey string
	Provider   domain.ProviderID
	Credential domain.CredentialID
	Model      domain.ModelID
	// Tokens is the total token count observed for the attempt (input+output).
	Tokens int
	// InputTokens and OutputTokens split Tokens when the provider reports them.
	InputTokens  int
	OutputTokens int
	// Requests is the number of upstream requests the attempt issued (usually 1).
	Requests int
	// CostMicros is the estimated cost in micro-units. 0 = unknown.
	CostMicros int64
	// Aborted marks a stream cut short (client disconnect, idle timeout) after
	// consuming quota. An aborted usage still reports the tokens observed up to
	// the abort (ADR-0011 §5); it replaces any earlier record for the same key.
	Aborted bool
}

// Response is the result of ONE winning attempt: the executor's WireResponse
// plus the provenance (which Candidate answered) for audit and accounting.
type Response struct {
	Candidate Candidate
	Wire      WireResponse
	// Attempts is how many attempts were consumed up to the winner (>= 1).
	Attempts int
}

// Dispatcher executes a RoutePlan. It owns the attempt loop, the failover and
// the accounting. It does NOT resolve a route (Router), apply content gates
// (GateChain) or serialize HTTP (api/openai).
//
// INVARIANTS (ADR-0010):
//   - A ScopeRequest result is TERMINAL: return immediately, do not retry and
//     do not Record.
//   - RetryAfter wins over the exponential backoff (ADR-0002 §3).
//   - ctx always wins: every cooldown wait selects on ctx.Done() and returns the
//     ctx error (never "candidates exhausted").
//   - committed (streaming): after the first downstream byte no candidate swap
//     is legal; a pre-commit failure is classified and fails over, a post-commit
//     failure becomes a terminal SSE event, never an HTTP error.
type Dispatcher interface {
	// Do executes a non-streaming plan and returns the winning Response.
	Do(ctx context.Context, req WireRequest, plan RoutePlan) (*Response, error)
	// DoStream executes a streaming plan. The returned Stream is bound to ctx
	// and becomes committed on the first byte.
	DoStream(ctx context.Context, req WireRequest, plan RoutePlan) (Stream, error)
}
