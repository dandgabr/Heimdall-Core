// Package breaker implements the circuit breaker of F3 (ADR-0012).
//
// # Position
//
// The breaker is consulted in the PREFLIGHT (Allow) and updated by the
// Dispatcher (Record). It is NOT a gate and NOT a quota: per ADR-0011/ADR-0012
// a credential may have an exhausted window and a CLOSED circuit, or the
// opposite — the two preflight checks are independent states.
//
// # Three scopes, one identity
//
// State is kept per contracts.BreakerKey, and a key is one of three
// granularities (ADR-0012 §1): Provider (an outage), Connection/Credential (one
// account) and Model (one provider+model pair). A ScopeProvider failure opens
// Provider AND Model (the model is a finer cut of the same signal); a
// ScopeCredential failure opens only the credential, so one banned account does
// not take down the other accounts of the family.
//
// # What it decides on
//
// The breaker classifies ONLY from the typed Outcome — Scope, Retryable,
// RetryAfter and TerminalReason. It NEVER parses a Code or an HTTPStatus
// (ADR-0002, ADR-0012 §2): a new error code must not require touching this
// package. A client-scoped failure is a NO-OP, which is the rule that stops a
// 400 from cooling down a healthy account.
//
// # State lives in MEMORY
//
// The state is per-process and ephemeral (ADR-0012 §6): restarting the daemon
// resets transient circuits. That is deliberate and opposite to durable quota
// (ADR-0011 §4): a forgotten circuit costs a few attempts to reopen; a forgotten
// quota window overspends the operator's plan. Terminal credential states may be
// mirrored durably elsewhere (the `credentials` table); this package does not
// persist anything.
//
// # Determinism
//
// The Clock and the Jitter are injected, so the exponential cooldown and the
// lazy Open->HalfOpen transition are testable without sleeping and without a
// probabilistic assertion.
package breaker

import (
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Terminal reasons (ADR-0012 §4.2). They are stored on a Terminal state so the
// GUI/CLI can explain WHY a credential was taken out of routing.
const (
	// TerminalBanned: the account was banned.
	TerminalBanned = "banned"
	// TerminalCreditsExhausted: the balance is zero with no reset.
	TerminalCreditsExhausted = "credits_exhausted"
	// TerminalExpired: the credential is expired or revoked.
	TerminalExpired = "expired"
)

// Outcome is the typed result of ONE attempt, as the Dispatcher extracts it from
// the DomainError (ADR-0012 §2/§6). Every field is typed; there is deliberately
// no Code-based classification path.
type Outcome struct {
	// Scope is the failure domain (ADR-0002). ScopeRequest is a no-op.
	Scope domain.ErrScope
	// Retryable mirrors DomainError.Retryable: a non-retryable credential
	// failure counts toward terminal promotion, a retryable one opens a
	// cooldown.
	Retryable bool
	// RetryAfter, when > 0, wins over the exponential backoff and is applied
	// EXACTLY (ADR-0002 §3, ADR-0012 §3): a 429 with a reset cools down to the
	// reset, not for an exponential duration.
	RetryAfter time.Duration
	// TerminalReason, when non-empty, makes the key TERMINAL immediately
	// (banned | credits_exhausted | expired). It is set by the Dispatcher from
	// the typed classification, never inferred here from a Code.
	TerminalReason string
	// Success marks a successful attempt. A success CLOSES the key immediately
	// (the strongest signal), unless the key is terminal.
	Success bool
}

// Config tunes the breaker. The zero value is replaced by DefaultConfig so a
// caller that only cares about behaviour is not forced to pick numbers.
type Config struct {
	// Base is the first cooldown of an exponential sequence.
	Base time.Duration
	// Max caps the exponential cooldown.
	Max time.Duration
	// CredentialThreshold is N in ADR-0002 §2: after N consecutive
	// non-retryable credential failures the credential becomes terminal.
	CredentialThreshold int
	// Jitter maps a computed cooldown to the actual one. Production uses
	// DefaultJitter ([0.5x,1.0x]); a test injects the identity to assert the
	// exact exponential sequence.
	Jitter func(time.Duration) time.Duration
}

// DefaultConfig returns the documented defaults: a 1s base, a 1m ceiling, and
// N=3 consecutive non-retryable credential failures before terminal promotion.
func DefaultConfig() Config {
	return Config{
		Base:                time.Second,
		Max:                 time.Minute,
		CredentialThreshold: 3,
		Jitter:              DefaultJitter,
	}
}

// DefaultJitter returns the cooldown scaled into [0.5x, 1.0x]. The spread
// desynchronises independent processes so they do not all retry at the same
// instant ("thundering herd", ADR-0012 §3).
func DefaultJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	factor := 0.5 + randFloat64()*0.5
	return time.Duration(float64(d) * factor)
}

// keyState is the mutable state of one circuit. A per-key mutex serializes
// Record and the probe reservation, which is what makes anti-thundering-herd
// hold without a global lock (ADR-0012 §3).
type keyState struct {
	mu sync.Mutex
	// status is the current circuit state.
	status contracts.BreakerState
	// failures is the consecutive-failure counter; reset on success.
	failures int
	// openUntil is when an Open circuit becomes eligible for a probe.
	openUntil time.Time
	// terminalReason explains a Terminal state (banned|credits_exhausted|expired).
	terminalReason string
	// probeInFlight is true while the single half-open probe is outstanding.
	probeInFlight bool
}

// Breaker is the concrete circuit breaker. It implements the frozen
// contracts.Breaker (Allow/OnResult/RetryAfter on a Candidate) and exposes the
// typed ADR-0012 API (State/AllowKey/RecordKey/RetryAfterKey on a BreakerKey).
//
// It is safe for concurrent use.
type Breaker struct {
	cfg   Config
	clock contracts.Clock

	mu   sync.Mutex
	keys map[contracts.BreakerKey]*keyState
}

var _ contracts.Breaker = (*Breaker)(nil)

// New builds a Breaker. A nil clock is a programming error and panics at
// construction rather than later inside a request.
func New(clock contracts.Clock, opts ...Option) *Breaker {
	if clock == nil {
		panic("breaker: nil clock")
	}
	b := &Breaker{cfg: DefaultConfig(), clock: clock, keys: make(map[contracts.BreakerKey]*keyState)}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Option customises a Breaker.
type Option func(*Breaker)

// WithConfig overrides the cooldown/threshold configuration. Zero fields fall
// back to DefaultConfig so a partial config cannot produce a zero base.
func WithConfig(cfg Config) Option {
	return func(b *Breaker) {
		def := DefaultConfig()
		if cfg.Base <= 0 {
			cfg.Base = def.Base
		}
		if cfg.Max <= 0 {
			cfg.Max = def.Max
		}
		if cfg.CredentialThreshold <= 0 {
			cfg.CredentialThreshold = def.CredentialThreshold
		}
		if cfg.Jitter == nil {
			cfg.Jitter = def.Jitter
		}
		b.cfg = cfg
	}
}

// keyOf returns the state for a key, creating it on first use. The map lock is
// held only for the lookup/create, never across a state transition.
func (b *Breaker) keyOf(k contracts.BreakerKey) *keyState {
	b.mu.Lock()
	ks := b.keys[k]
	if ks == nil {
		ks = &keyState{}
		b.keys[k] = ks
	}
	b.mu.Unlock()
	return ks
}

// now is the injectable time source.
func (b *Breaker) now() time.Time { return b.clock.Now() }

// transitionLocked performs the lazy Open->HalfOpen transition (ADR-0012 §5):
// when the cooldown has elapsed, the circuit becomes HalfOpen on READ. It leaves
// the failure counter untouched.
func (ks *keyState) transitionLocked(now time.Time) {
	if ks.status == contracts.BreakerOpen && !ks.openUntil.After(now) {
		ks.status = contracts.BreakerHalfOpen
		ks.probeInFlight = false
	}
}

// State returns the current state of a key, applying the lazy Open->HalfOpen
// transition. It never changes the failure counter.
func (b *Breaker) State(k contracts.BreakerKey) contracts.BreakerState {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.transitionLocked(b.now())
	return ks.status
}

// AllowKey reports whether a key may be attempted now. In HalfOpen it reserves
// the single probe: the FIRST caller is allowed, later callers see Open until
// the probe resolves (ADR-0012 §5).
func (b *Breaker) AllowKey(k contracts.BreakerKey) bool {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.transitionLocked(b.now())
	return ks.reserveLocked()
}

// reserveLocked implements the probe reservation under the key lock.
func (ks *keyState) reserveLocked() bool {
	switch ks.status {
	case contracts.BreakerClosed:
		return true
	case contracts.BreakerHalfOpen:
		if ks.probeInFlight {
			return false
		}
		ks.probeInFlight = true
		return true
	default: // Open or Terminal
		return false
	}
}

// releaseProbe releases a reservation this caller made but will not use, so a
// cross-scope denial in Allow does not strand the probe slot.
func (ks *keyState) releaseProbe() {
	if ks.status == contracts.BreakerHalfOpen {
		ks.probeInFlight = false
	}
}

// RetryAfterKey returns the remaining cooldown of a key; zero means it is not
// open (Closed, HalfOpen or Terminal).
func (b *Breaker) RetryAfterKey(k contracts.BreakerKey) time.Duration {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.transitionLocked(b.now())
	if ks.status != contracts.BreakerOpen {
		return 0
	}
	// After the lazy transition, a still-Open key has openUntil strictly in the
	// future, so the remaining duration is positive by construction.
	return ks.openUntil.Sub(b.now())
}

// TerminalReason returns the reason of a Terminal key, or "" when the key is not
// terminal. It is observability for the GUI/CLI (ADR-0012 §4.2).
func (b *Breaker) TerminalReason(k contracts.BreakerKey) string {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.status != contracts.BreakerTerminal {
		return ""
	}
	return ks.terminalReason
}

// RecordKey applies the typed result of ONE attempt to ONE key. It is the only
// mutator of that key. It decides solely on the typed Outcome fields.
func (b *Breaker) RecordKey(k contracts.BreakerKey, o Outcome) {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	now := b.now()
	ks.transitionLocked(now)

	// A terminal state is ABSORVENTE: a transient outcome (or even a success)
	// never reopens it; only an explicit Clear does (ADR-0012 §4.1).
	if ks.status == contracts.BreakerTerminal {
		return
	}

	if o.Success {
		ks.status = contracts.BreakerClosed
		ks.failures = 0
		ks.openUntil = time.Time{}
		ks.probeInFlight = false
		return
	}

	// A client error NEVER records (ADR-0012 §2): the request is at fault, so
	// another credential cannot help and cooling this one down would be wrong.
	if o.Scope == domain.ScopeRequest {
		return
	}

	// An explicit terminal reason promotes immediately, whatever the scope.
	if o.TerminalReason != "" {
		ks.status = contracts.BreakerTerminal
		ks.terminalReason = o.TerminalReason
		ks.openUntil = time.Time{}
		ks.probeInFlight = false
		return
	}

	// Non-retryable PROVIDER failures are deterministic (e.g.
	// error.upstream_response_too_large): not an outage, so no cooldown.
	if o.Scope == domain.ScopeProvider && !o.Retryable {
		return
	}

	ks.failures++

	// Non-retryable CREDENTIAL failures do not open a cooldown; they count
	// toward the N-failure terminal promotion (ADR-0002 §2, ADR-0012 §4.3).
	if o.Scope == domain.ScopeCredential && !o.Retryable {
		if ks.failures >= b.cfg.CredentialThreshold {
			ks.status = contracts.BreakerTerminal
			ks.terminalReason = TerminalBanned
			ks.openUntil = time.Time{}
			ks.probeInFlight = false
		}
		return
	}

	// Retryable failure: open with a cooldown. RetryAfter (quota/429) wins and
	// is exact; otherwise the exponential backoff with a ceiling and jitter.
	var cooldown time.Duration
	if o.RetryAfter > 0 {
		cooldown = o.RetryAfter
	} else {
		cooldown = b.exponential(ks.failures)
	}

	// Anti-thundering-herd (ADR-0012 §3): when the circuit is ALREADY open, a
	// concurrent failure does not push OpenUntil further out. It only feeds the
	// exponent for the next reopen, and releases any probe slot.
	if ks.status == contracts.BreakerOpen && ks.openUntil.After(now) {
		ks.probeInFlight = false
		return
	}
	ks.status = contracts.BreakerOpen
	ks.openUntil = now.Add(cooldown)
	ks.probeInFlight = false
}

// exponential is min(Base * 2^(failures-1), Max) with jitter applied. failures
// is >= 1 at the call site.
func (b *Breaker) exponential(failures int) time.Duration {
	shift := failures - 1
	// Cap the shift so a long failure streak cannot overflow the Duration.
	const maxShift = 30
	if shift > maxShift {
		shift = maxShift
	}
	d := b.cfg.Base << uint(shift)
	if d <= 0 || d > b.cfg.Max {
		d = b.cfg.Max
	}
	return b.cfg.Jitter(d)
}

// Clear resets a key to Closed, discarding any terminal state. It is the
// EXPLICIT human action ADR-0012 §4.1 requires to reopen a terminal circuit
// (e.g. after reauthenticating or swapping the key).
func (b *Breaker) Clear(k contracts.BreakerKey) {
	ks := b.keyOf(k)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.status = contracts.BreakerClosed
	ks.failures = 0
	ks.openUntil = time.Time{}
	ks.terminalReason = ""
	ks.probeInFlight = false
}

// --- typed fan-out over a Candidate (ADR-0012 §1) ---

// keysFor returns the keys a candidate touches for a failure scope, in scope
// order. A credential failure opens only the credential; a provider failure
// opens Provider AND Model (ADR-0012 §1.1).
func keysFor(c contracts.Candidate, scope domain.ErrScope) []contracts.BreakerKey {
	switch scope {
	case domain.ScopeCredential:
		if c.Credential == "" {
			return nil
		}
		return []contracts.BreakerKey{contracts.KeyFor(c, contracts.BreakerCredential)}
	case domain.ScopeProvider:
		out := []contracts.BreakerKey{contracts.KeyFor(c, contracts.BreakerProvider)}
		if c.Model != "" {
			out = append(out, contracts.KeyFor(c, contracts.BreakerModel))
		}
		return out
	default:
		return nil
	}
}

// allKeysFor is the set a success closes: every scope the candidate touches.
func allKeysFor(c contracts.Candidate) []contracts.BreakerKey {
	out := []contracts.BreakerKey{contracts.KeyFor(c, contracts.BreakerProvider)}
	if c.Model != "" {
		out = append(out, contracts.KeyFor(c, contracts.BreakerModel))
	}
	if c.Credential != "" {
		out = append(out, contracts.KeyFor(c, contracts.BreakerCredential))
	}
	return out
}

// Record applies a typed outcome to a candidate, fanning out per scope. It is
// the Dispatcher's entry point (ADR-0012 §6).
func (b *Breaker) Record(c contracts.Candidate, o Outcome) {
	if o.Success {
		for _, k := range allKeysFor(c) {
			b.RecordKey(k, Outcome{Success: true})
		}
		return
	}
	for _, k := range keysFor(c, o.Scope) {
		b.RecordKey(k, o)
	}
}

// --- frozen contracts.Breaker adapter ---

// Allow implements contracts.Breaker: the candidate may be attempted only if
// every scope it touches is closed (or a probe is available). A zero credential
// means the Dispatcher will pick one, so only Provider/Model are checked here.
// If a later key denies after an earlier one reserved its probe, the reservation
// is released so the probe slot is not stranded.
func (b *Breaker) Allow(c contracts.Candidate) bool {
	var reserved []*keyState
	for _, k := range allKeysFor(c) {
		ks := b.keyOf(k)
		ks.mu.Lock()
		ks.transitionLocked(b.now())
		ok := ks.reserveLocked()
		ks.mu.Unlock()
		if !ok {
			for _, r := range reserved {
				r.mu.Lock()
				r.releaseProbe()
				r.mu.Unlock()
			}
			return false
		}
		reserved = append(reserved, ks)
	}
	return true
}

// RetryAfter implements contracts.Breaker: the longest cooldown among the
// candidate's keys, or zero when none is open.
func (b *Breaker) RetryAfter(c contracts.Candidate) time.Duration {
	var max time.Duration
	for _, k := range allKeysFor(c) {
		if d := b.RetryAfterKey(k); d > max {
			max = d
		}
	}
	return max
}

// OnResult implements contracts.Breaker. It maps the coarse AttemptOutcome onto
// the typed Outcome and fans out to the candidate's keys.
//
// Limitation, documented: the frozen OnResult carries neither RetryAfter nor a
// terminal reason (only AttemptOutcome), so this path applies the exponential
// cooldown for credential/provider errors and can never promote a terminal. The
// Dispatcher uses the typed Record for the exact RetryAfter and terminal paths,
// exactly as ADR-0012 §6 specifies.
func (b *Breaker) OnResult(c contracts.Candidate, outcome contracts.AttemptOutcome, _ contracts.Usage) {
	switch outcome {
	case contracts.OutcomeSuccess:
		b.Record(c, Outcome{Success: true})
	case contracts.OutcomeCredentialError:
		b.Record(c, Outcome{Scope: domain.ScopeCredential, Retryable: true})
	case contracts.OutcomeProviderError:
		b.Record(c, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	default:
		// OutcomeClientError and OutcomeTransient never record (ADR-0012 §2).
	}
}
