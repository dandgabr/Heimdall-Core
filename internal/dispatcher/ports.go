// Package dispatcher implements the contracts.Dispatcher of F3 (ADR-0010).
//
// The Dispatcher is the OWNER of the attempt loop, the failover and the
// accounting: it receives a RoutePlan already resolved and filtered by the
// Router, consults the breaker and the quota filter before each attempt, talks
// to the family's Executor, classifies the result by the TYPED Scope/Retryable
// (never by Code or HTTPStatus, ADR-0002) and reports usage per attempt.
//
// # Position
//
// It does NOT resolve a route (Router), apply a content gate (GateChain) or
// serialize HTTP (api/openai). The three dependencies ADR-0010 §"Consequências"
// names are injected: an ExecutorFactory (by family/credential), a QuotaFilter
// and a Breaker. Clock/IDGen are the determinism seams; the UsageRecorder is an
// optional observer (nil = no accounting), so the loop is not coupled to a
// concrete recorder.
//
// # Streaming
//
// DoStream returns the stream of the FIRST candidate that opens one; from that
// point the choice is committed and no swap is legal (the frozen
// contracts.Stream marks `committed` on the first downstream byte, and the
// dispatcher never re-enters the loop after a stream is returned). A pre-commit
// failure (non-2xx, transport) is an error from DoStream and fails over
// normally; a post-commit Recv error is delivered in-band by the HTTP layer as a
// terminal SSE event, never as an HTTP status change.
package dispatcher

import (
	"context"
	"time"

	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ExecutorFactory builds the Executor for a candidate's provider family and a
// concrete credential (ADR-0001: the Executor is per family+credential). The
// composition root adapts the provider registry to it.
type ExecutorFactory interface {
	// Build returns the executor for the candidate's family bound to cred. The
	// credential is passed by value (ADR-0001) and its secret is opened inside
	// the executor, never here.
	Build(ctx context.Context, c contracts.Candidate, cred contracts.Credential) (contracts.Executor, error)
}

// CredentialSource lists and loads credentials. It is what the Dispatcher uses
// to pick a healthy account when the plan's candidate has a zero Credential
// ("any healthy credential of the family", ADR-0009 §1). The store's
// CredentialStore satisfies the load half; the composition root adapts the list
// half.
type CredentialSource interface {
	// Get loads one credential by id, or a not-found error.
	Get(ctx context.Context, id domain.CredentialID) (contracts.Credential, error)
	// Credentials returns the known credentials of a provider, deterministically
	// ordered. The first healthy one is chosen.
	Credentials(ctx context.Context, provider domain.ProviderID) ([]domain.CredentialID, error)
}

// Breaker is the preflight circuit breaker (ADR-0012). It is the concrete
// breaker's typed surface: Record takes the typed breaker.Outcome, never a Code
// or HTTPStatus. *breaker.Breaker satisfies it directly.
type Breaker interface {
	// Allow reports whether a candidate may be attempted now.
	Allow(c contracts.Candidate) bool
	// Record applies the typed result of one attempt.
	Record(c contracts.Candidate, o breaker.Outcome)
	// RetryAfter reports the remaining cooldown of a candidate; zero means it is
	// not open.
	RetryAfter(c contracts.Candidate) time.Duration
}

// Waiter is the cooldown wait seam. The frozen contracts.Clock exposes only
// Now() (no After/Sleep), so the Dispatcher takes this narrow port to honour a
// RetryAfter between attempts without a real sleep in tests. Production uses a
// context-aware timer; a test injects a fake that records the requested delay.
type Waiter interface {
	// Wait blocks for d, or until ctx is done, whichever first. It returns the
	// ctx error when it was cancelled.
	Wait(ctx context.Context, d time.Duration) error
}

// QuotaFilter is the preflight quota check the Dispatcher consults before an
// attempt (ADR-0010 §2 step 1). *quota.Filter satisfies it. A nil filter means
// "no quota filtering".
type QuotaFilter interface {
	Filter(ctx context.Context, plan contracts.RoutePlan) (contracts.RoutePlan, []contracts.Skip)
}
