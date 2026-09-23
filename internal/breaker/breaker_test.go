package breaker

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fixedClock is the injectable time source. Advancing it is the only way a test
// moves a cooldown forward, so no test sleeps.
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestBreaker(t *testing.T, cfg Config) (*Breaker, *fixedClock) {
	t.Helper()
	clock := &fixedClock{t: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	b := New(clock, WithConfig(cfg))
	return b, clock
}

// identityJitter removes the spread so the exponential sequence is exact.
func identityJitter(d time.Duration) time.Duration { return d }

func testCfg() Config {
	return Config{
		Base:                time.Second,
		Max:                 time.Minute,
		CredentialThreshold: 3,
		Jitter:              identityJitter,
	}
}

func credCandidate() contracts.Candidate {
	return contracts.Candidate{Provider: "zai", Model: "glm", Credential: "acct-1"}
}

func TestNewRejectsNilClock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(nil clock) did not panic")
		}
	}()
	New(nil)
}

func TestWithConfigFillsDefaults(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	b := New(clock, WithConfig(Config{}))
	if b.cfg.Base != DefaultConfig().Base {
		t.Errorf("Base = %v, want default", b.cfg.Base)
	}
	if b.cfg.Max != DefaultConfig().Max {
		t.Errorf("Max = %v, want default", b.cfg.Max)
	}
	if b.cfg.CredentialThreshold != DefaultConfig().CredentialThreshold {
		t.Errorf("Threshold = %d, want default", b.cfg.CredentialThreshold)
	}
	if b.cfg.Jitter == nil {
		t.Error("Jitter not defaulted")
	}
}

func TestDefaultJitterRange(t *testing.T) {
	// Pin the entropy seam so the jitter is deterministic, then prove the
	// [0.5x,1.0x) bounds at both ends and the zero guard.
	orig := randFloat64
	defer func() { randFloat64 = orig }()

	randFloat64 = func() float64 { return 0 }
	if got := DefaultJitter(time.Second); got != 500*time.Millisecond {
		t.Errorf("DefaultJitter low end = %v, want 500ms", got)
	}
	randFloat64 = func() float64 { return 1 }
	if got := DefaultJitter(time.Second); got != time.Second {
		t.Errorf("DefaultJitter high end = %v, want 1s", got)
	}
	if got := DefaultJitter(0); got != 0 {
		t.Errorf("DefaultJitter(0) = %v, want 0", got)
	}
	if got := DefaultJitter(-time.Second); got != 0 {
		t.Errorf("DefaultJitter(negative) = %v, want 0", got)
	}
}

// TestClientErrorNeverRecords is the ADR-0012 headline test: a 400 must not
// cool down a healthy account. Zero transitions.
func TestClientErrorNeverRecords(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerCredential)

	b.RecordKey(k, Outcome{Scope: domain.ScopeRequest})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("state after client error = %v, want closed", got)
	}
	if b.RetryAfterKey(k) != 0 {
		t.Fatal("client error produced a cooldown")
	}
	_ = clock
}

func TestProviderErrorOpensProviderAndModel(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.Record(c, Outcome{Scope: domain.ScopeProvider, Retryable: true})

	pk := contracts.KeyFor(c, contracts.BreakerProvider)
	mk := contracts.KeyFor(c, contracts.BreakerModel)
	if got := b.State(pk); got != contracts.BreakerOpen {
		t.Fatalf("provider state = %v, want open", got)
	}
	if got := b.State(mk); got != contracts.BreakerOpen {
		t.Fatalf("model state = %v, want open", got)
	}
	// The credential scope is NOT opened by a provider failure.
	if got := b.State(contracts.KeyFor(c, contracts.BreakerCredential)); got != contracts.BreakerClosed {
		t.Fatalf("credential state = %v, want closed", got)
	}

	// Exponential base 1s for the first failure.
	if got := b.RetryAfterKey(pk); got != time.Second {
		t.Fatalf("retry after = %v, want 1s", got)
	}
	// A second provider failure while still open must NOT extend the cooldown
	// (anti-thundering-herd, ADR-0012 §3).
	b.Record(c, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	if got := b.RetryAfterKey(pk); got != time.Second {
		t.Fatalf("duplicate failure extended cooldown to %v", got)
	}
	_ = clock
}

func TestCredentialErrorOpensOnlyCredential(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.Record(c, Outcome{Scope: domain.ScopeCredential, Retryable: true})

	if got := b.State(contracts.KeyFor(c, contracts.BreakerCredential)); got != contracts.BreakerOpen {
		t.Fatalf("credential state = %v, want open", got)
	}
	// Quota/429 is ScopeCredential and must NEVER open the provider circuit
	// (ADR-0011 §6).
	if got := b.State(contracts.KeyFor(c, contracts.BreakerProvider)); got != contracts.BreakerClosed {
		t.Fatalf("provider state = %v, want closed", got)
	}
}

// TestRetryAfterIsExact proves ADR-0012 §3: a RetryAfter wins over the
// exponential and is applied exactly.
func TestRetryAfterIsExact(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.Record(c, Outcome{Scope: domain.ScopeCredential, Retryable: true, RetryAfter: 42 * time.Second})
	k := contracts.KeyFor(c, contracts.BreakerCredential)
	if got := b.RetryAfterKey(k); got != 42*time.Second {
		t.Fatalf("retry after = %v, want exactly 42s", got)
	}
}

// TestExponentialWithCeiling drives the exponent and proves the Max ceiling.
func TestExponentialWithCeiling(t *testing.T) {
	cfg := testCfg()
	cfg.Base = time.Second
	cfg.Max = 4 * time.Second
	b, clock := newTestBreaker(t, cfg)
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerProvider)

	// Each failure happens after the previous cooldown elapses, so the circuit
	// reopens with the next exponent (1s, 2s, 4s, then capped at 4s).
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		clock.advance(b.RetryAfterKey(k) + time.Millisecond)
		b.RecordKey(k, Outcome{Scope: domain.ScopeProvider, Retryable: true})
		if got := b.RetryAfterKey(k); got != want {
			t.Fatalf("failure %d: cooldown = %v, want %v", i, got, want)
		}
	}
}

func TestExponentialShiftIsCapped(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	// A failure count past the shift cap must not overflow; the Max ceiling
	// wins. Call exponential directly to reach the guarded branch.
	if got := b.exponential(1000); got != b.cfg.Max {
		t.Fatalf("exponential(1000) = %v, want Max %v", got, b.cfg.Max)
	}
}

// TestNonRetryableCredentialPromotesTerminalAfterN proves ADR-0002 §2 /
// ADR-0012 §4.3: N=3 consecutive non-retryable credential failures promote to
// Terminal{banned} WITHOUT passing through Open.
func TestNonRetryableCredentialPromotesTerminalAfterN(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerCredential)

	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("after 1 failure = %v, want still closed (no cooldown)", got)
	}
	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("after 2 failures = %v, want still closed", got)
	}
	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	if got := b.State(k); got != contracts.BreakerTerminal {
		t.Fatalf("after 3 failures = %v, want terminal", got)
	}
	if reason := b.TerminalReason(k); reason != TerminalBanned {
		t.Fatalf("terminal reason = %q, want %q", reason, TerminalBanned)
	}
}

// TestSuccessResetsFailureCounter proves a success zeroes the streak so N
// failures must be CONSECUTIVE.
func TestSuccessResetsFailureCounter(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerCredential)

	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	b.RecordKey(k, Outcome{Success: true})
	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, Retryable: false})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("non-consecutive failures promoted to %v", got)
	}
}

// TestTerminalIsAbsorvent proves ADR-0012 §4.1: a transient cooldown (and even a
// success) never reopens a terminal key.
func TestTerminalIsAbsorvent(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerCredential)

	b.RecordKey(k, Outcome{Scope: domain.ScopeCredential, TerminalReason: TerminalExpired})
	if got := b.State(k); got != contracts.BreakerTerminal {
		t.Fatalf("state = %v, want terminal", got)
	}
	// A transient outage.
	b.RecordKey(k, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	// A success.
	b.RecordKey(k, Outcome{Success: true})
	// Time passing.
	clock.advance(24 * time.Hour)
	if got := b.State(k); got != contracts.BreakerTerminal {
		t.Fatalf("terminal was reopened to %v", got)
	}
	if reason := b.TerminalReason(k); reason != TerminalExpired {
		t.Fatalf("terminal reason = %q, want %q", reason, TerminalExpired)
	}

	// Clear is the explicit human action that reopens it.
	b.Clear(k)
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("after Clear = %v, want closed", got)
	}
	if reason := b.TerminalReason(k); reason != "" {
		t.Fatalf("reason after Clear = %q, want empty", reason)
	}
}

// TestNonRetryableProviderDoesNotCooldown proves a deterministic provider error
// (e.g. error.upstream_response_too_large) is not an outage.
func TestNonRetryableProviderDoesNotCooldown(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerProvider)
	b.RecordKey(k, Outcome{Scope: domain.ScopeProvider, Retryable: false})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("state = %v, want closed", got)
	}
}

// TestHalfOpenSingleProbeAndRecovery proves ADR-0012 §5: after the cooldown the
// circuit is HalfOpen on READ, exactly ONE probe is allowed, a success closes it,
// and a failed probe reopens with the doubled cooldown.
func TestHalfOpenSingleProbeAndRecovery(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerProvider)

	b.Record(c, Outcome{Scope: domain.ScopeProvider, Retryable: true}) // 1s
	clock.advance(time.Second)

	if got := b.State(k); got != contracts.BreakerHalfOpen {
		t.Fatalf("state after cooldown = %v, want half_open", got)
	}
	if !b.AllowKey(k) {
		t.Fatal("first Allow in half-open was denied")
	}
	if b.AllowKey(k) {
		t.Fatal("second Allow in half-open was granted (probe not exclusive)")
	}
	// A failed probe doubles the exponent (2 failures -> 2s) and reopens.
	clock.advance(time.Second)
	b.RecordKey(k, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	if got := b.State(k); got != contracts.BreakerOpen {
		t.Fatalf("state after failed probe = %v, want open", got)
	}
	if got := b.RetryAfterKey(k); got != 2*time.Second {
		t.Fatalf("cooldown after failed probe = %v, want 2s", got)
	}

	// A successful probe closes the circuit.
	clock.advance(2 * time.Second)
	if !b.AllowKey(k) {
		t.Fatal("probe after second cooldown was denied")
	}
	b.RecordKey(k, Outcome{Success: true})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("state after successful probe = %v, want closed", got)
	}
	if b.RetryAfterKey(k) != 0 {
		t.Fatal("closed circuit reported a cooldown")
	}
}

// TestAllowReleasesProbeOnCrossScopeDenial covers the reservation-release path:
// when a later scope denies, the earlier reserved probe must not be stranded.
func TestAllowReleasesProbeOnCrossScopeDenial(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()

	// Model is half-open (probe available), Provider is open: Allow checks
	// Provider first (denied) so Model's probe is never reserved; then we flip
	// so Model is checked after a successful Provider reservation and denied.
	mk := contracts.KeyFor(c, contracts.BreakerModel)
	b.RecordKey(mk, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	clock.advance(time.Second) // Model -> HalfOpen
	pk := contracts.KeyFor(c, contracts.BreakerProvider)
	b.RecordKey(pk, Outcome{Scope: domain.ScopeProvider, Retryable: true})

	// Provider is open -> Allow false. Now let Provider go half-open too, but
	// consume its probe directly so a candidate touches a granted Provider then
	// a denied Model.
	clock.advance(time.Second)
	if !b.AllowKey(pk) {
		t.Fatal("provider probe denied")
	}
	// Model probe is still free; consume it via a raw AllowKey to prove the
	// release path indirectly. Instead, construct the exact case: an open Model
	// AFTER a granted Provider.
	modelKey := contracts.KeyFor(c, contracts.BreakerCredential)
	b.RecordKey(modelKey, Outcome{Scope: domain.ScopeCredential, Retryable: true})

	// Reset: provider closed so Allow reserves it, credential open so the
	// second check denies and the provider probe is released.
	b.Clear(pk)
	b.Clear(mk)
	b.RecordKey(modelKey, Outcome{Scope: domain.ScopeCredential, Retryable: true})
	if b.Allow(c) {
		t.Fatal("Allow granted with a credential-scope circuit open")
	}
	// Provider was reserved then released: a fresh Allow must be able to reserve
	// it again once the credential circuit is cleared.
	if !b.AllowKey(pk) {
		t.Fatal("provider probe was stranded after a cross-scope denial")
	}
}

func TestRetryAfterUsesLongestKey(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.RecordKey(contracts.KeyFor(c, contracts.BreakerProvider),
		Outcome{Scope: domain.ScopeProvider, Retryable: true, RetryAfter: 10 * time.Second})
	b.RecordKey(contracts.KeyFor(c, contracts.BreakerModel),
		Outcome{Scope: domain.ScopeProvider, Retryable: true, RetryAfter: 30 * time.Second})
	if got := b.RetryAfter(c); got != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want the longest (30s)", got)
	}
}

func TestRetryAfterZeroWhenNotOpen(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	if b.RetryAfter(c) != 0 {
		t.Fatal("a closed candidate reported a cooldown")
	}
	if b.RetryAfterKey(contracts.KeyFor(c, contracts.BreakerCredential)) != 0 {
		t.Fatal("closed key reported a cooldown")
	}
}

// TestOnResultAdapter covers the frozen-contract adapter: success closes,
// credential/provider map to their scopes, client error is a no-op.
func TestOnResultAdapter(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerProvider)

	b.OnResult(c, contracts.OutcomeClientError, contracts.Usage{})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("client error through OnResult opened %v", got)
	}
	b.OnResult(c, contracts.OutcomeProviderError, contracts.Usage{})
	if got := b.State(k); got != contracts.BreakerOpen {
		t.Fatalf("provider error through OnResult = %v, want open", got)
	}
	b.OnResult(c, contracts.OutcomeSuccess, contracts.Usage{})
	if got := b.State(k); got != contracts.BreakerClosed {
		t.Fatalf("success through OnResult = %v, want closed", got)
	}
	b.OnResult(c, contracts.OutcomeCredentialError, contracts.Usage{})
	if got := b.State(contracts.KeyFor(c, contracts.BreakerCredential)); got != contracts.BreakerOpen {
		t.Fatalf("credential error through OnResult = %v, want open", got)
	}
	// Transient is a documented no-op.
	b.OnResult(contracts.Candidate{Provider: "p", Model: "m"}, contracts.OutcomeTransient, contracts.Usage{})
	if got := b.State(contracts.KeyFor(contracts.Candidate{Provider: "p", Model: "m"}, contracts.BreakerProvider)); got != contracts.BreakerClosed {
		t.Fatalf("transient outcome opened %v", got)
	}
}

// TestCandidateWithoutCredential covers the fan-out guards for a candidate that
// has no credential (the Dispatcher picks one), and the model-less candidate.
func TestCandidateWithoutCredential(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := contracts.Candidate{Provider: "p"} // no model, no credential
	// A credential failure on a zero-credential candidate has no key: no-op.
	b.Record(c, Outcome{Scope: domain.ScopeCredential, Retryable: true})
	if got := b.State(contracts.KeyFor(c, contracts.BreakerProvider)); got != contracts.BreakerClosed {
		t.Fatalf("credential error without a credential touched provider: %v", got)
	}
	// A provider failure opens Provider only (no model key).
	b.Record(c, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	if got := b.State(contracts.KeyFor(c, contracts.BreakerProvider)); got != contracts.BreakerOpen {
		t.Fatalf("provider failure = %v, want open", got)
	}
	// A success closes Provider even without model/credential keys.
	b.Record(c, Outcome{Success: true})
	if got := b.State(contracts.KeyFor(c, contracts.BreakerProvider)); got != contracts.BreakerClosed {
		t.Fatalf("success = %v, want closed", got)
	}
}

// TestKeyForScopesAndStrings covers the frozen KeyFor derivation and the
// String() methods (also for the enum coverage tests).
func TestKeyForScopesAndStrings(t *testing.T) {
	c := credCandidate()
	if k := contracts.KeyFor(c, contracts.BreakerProvider); k.Model != "" || k.Credential != "" {
		t.Fatalf("provider key carries extra fields: %+v", k)
	}
	if k := contracts.KeyFor(c, contracts.BreakerModel); k.Model != "glm" {
		t.Fatalf("model key = %+v", k)
	}
	if k := contracts.KeyFor(c, contracts.BreakerCredential); k.Credential != "acct-1" {
		t.Fatalf("credential key = %+v", k)
	}
	if contracts.BreakerProvider.String() != "provider" ||
		contracts.BreakerCredential.String() != "credential" ||
		contracts.BreakerModel.String() != "model" ||
		contracts.BreakerScope(99).String() != "unknown" {
		t.Fatal("BreakerScope.String mismatch")
	}
	if contracts.BreakerClosed.String() != "closed" ||
		contracts.BreakerOpen.String() != "open" ||
		contracts.BreakerHalfOpen.String() != "half_open" ||
		contracts.BreakerTerminal.String() != "terminal" ||
		contracts.BreakerState(99).String() != "unknown" {
		t.Fatal("BreakerState.String mismatch")
	}
}

// TestTerminalReasonEmptyWhenNotTerminal covers the non-terminal reason branch.
func TestTerminalReasonEmptyWhenNotTerminal(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	if got := b.TerminalReason(contracts.KeyFor(credCandidate(), contracts.BreakerCredential)); got != "" {
		t.Fatalf("reason for a fresh key = %q, want empty", got)
	}
}

// TestRecordRequestScopeIsNoop covers keysFor's default branch: a
// client-scoped outcome fans out to no key at all.
func TestRecordRequestScopeIsNoop(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.Record(c, Outcome{Scope: domain.ScopeRequest})
	if got := b.State(contracts.KeyFor(c, contracts.BreakerProvider)); got != contracts.BreakerClosed {
		t.Fatalf("client-scoped Record opened provider: %v", got)
	}
}

// TestAllowAllClosed covers the all-closed fast path.
func TestAllowAllClosed(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	if !b.Allow(credCandidate()) {
		t.Fatal("Allow denied an all-closed candidate")
	}
}

// TestAllowDeniedWithNoReservation covers the denial path with an empty
// reservation set (the first key is already open).
func TestAllowDeniedWithNoReservation(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	b.RecordKey(contracts.KeyFor(c, contracts.BreakerProvider),
		Outcome{Scope: domain.ScopeProvider, Retryable: true})
	if b.Allow(c) {
		t.Fatal("Allow granted with the provider circuit open")
	}
}

// TestAllowReleasesHalfOpenProbe covers releaseProbe's HalfOpen branch: the
// provider reserves its probe, a later key denies, and the probe must be
// released so it is not stranded.
func TestAllowReleasesHalfOpenProbe(t *testing.T) {
	b, clock := newTestBreaker(t, testCfg())
	c := credCandidate()
	pk := contracts.KeyFor(c, contracts.BreakerProvider)
	mk := contracts.KeyFor(c, contracts.BreakerModel)

	// Provider -> HalfOpen (probe free) after its cooldown elapses.
	b.RecordKey(pk, Outcome{Scope: domain.ScopeProvider, Retryable: true})
	clock.advance(time.Second)
	// Model -> Open now (a fresh failure AFTER the advance), so it denies while
	// the provider probe is available.
	b.RecordKey(mk, Outcome{Scope: domain.ScopeProvider, Retryable: true})

	// allKeysFor checks Provider first (reserves the probe), then Model (open,
	// denies). Allow must return false AND release the provider probe.
	if b.Allow(c) {
		t.Fatal("Allow granted with the model circuit open")
	}
	// The probe is free again: a direct reservation succeeds.
	if !b.AllowKey(pk) {
		t.Fatal("half-open provider probe was stranded after a cross-scope denial")
	}
}

// TestConcurrentAntiThunderingHerd runs many concurrent provider failures on one
// key and proves the cooldown is not extended per caller: it equals the base
// cooldown of a single first failure. It must be race-free (-race).
func TestConcurrentAntiThunderingHerd(t *testing.T) {
	b, _ := newTestBreaker(t, testCfg())
	c := credCandidate()
	k := contracts.KeyFor(c, contracts.BreakerProvider)

	const n = 64
	var wg sync.WaitGroup
	var granted int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if b.AllowKey(k) {
				atomic.AddInt64(&granted, 1)
			}
			b.RecordKey(k, Outcome{Scope: domain.ScopeProvider, Retryable: true})
		}()
	}
	close(start)
	wg.Wait()

	if got := b.RetryAfterKey(k); got != time.Second {
		t.Fatalf("concurrent failures extended the cooldown to %v, want 1s", got)
	}
	// A closed circuit admits everyone until the first failure opens it; the
	// exact count is racy, but there must be at least one.
	if atomic.LoadInt64(&granted) < 1 {
		t.Fatal("no concurrent caller was admitted before the circuit opened")
	}
}
