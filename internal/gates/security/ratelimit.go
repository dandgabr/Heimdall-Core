package security

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// RateLimiter throttles requests per CLIENT KEY with a deterministic token
// bucket: capacity = rate, refill rate/interval per second, all time taken
// from the injected contracts.Clock so tests are exact. On exhaustion the gate
// returns a Block whose synthetic response is 429 with a Retry-After header —
// the client is throttled, nothing upstream is touched (ADR-SEC-04 §1.1).
//
// The client key is metadata, never payload: the gate does not need the body
// and cannot read a header VALUE (GateInput.Headers carries names only). The
// key comes from KeyOf — by default the Meta["client.key"] the HTTP boundary
// sets, falling back to the resolved credential id and finally to one shared
// bucket — so the limiter works before routing has resolved anything.
//
// FailurePolicy is FailOpen: throttling is availability machinery with the
// same posture as quota (a limiter failure degrades to unthrottled service; it
// never aborts inference). It writes no security field, so the registry
// accepts the declaration (ADR-0014 §3.4).
//
// State lives in the gate and is mutex-guarded: gates are shared across
// concurrent requests, and the bucket map is the one piece of state whose
// whole point is surviving across them.
type RateLimiter struct {
	mu       sync.Mutex
	rate     int
	interval time.Duration
	clock    contracts.Clock
	keyOf    func(contracts.GateInput) string
	buckets  map[string]*tokenBucket
}

// tokenBucket is one key's bucket. tokens is a float so partial refills
// accumulate; capacity is rate.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// Compile-time assertions.
var (
	_ contracts.Gate         = (*RateLimiter)(nil)
	_ contracts.GateDeclarer = (*RateLimiter)(nil)
)

// RateLimitConfig configures the gate.
type RateLimitConfig struct {
	// Rate is the bucket capacity: the burst size and the number of requests
	// refilled per interval. Rate <= 0 disables the gate (nil is returned).
	Rate int
	// Interval is the refill period. Interval <= 0 disables the gate.
	Interval time.Duration
	// Clock is the time source. Nil falls back to the system clock.
	Clock contracts.Clock
	// KeyOf derives the client key from the gate input. Nil falls back to
	// defaultKeyOf (Meta["client.key"] → credential → shared "default").
	KeyOf func(contracts.GateInput) string
}

// NewRateLimit builds the gate, or nil when Rate/Interval do not define a
// working limiter — a misconfigured gate is not constructed.
func NewRateLimit(cfg RateLimitConfig) *RateLimiter {
	if cfg.Rate <= 0 || cfg.Interval <= 0 {
		return nil
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	keyOf := cfg.KeyOf
	if keyOf == nil {
		keyOf = defaultKeyOf
	}
	return &RateLimiter{
		rate:     cfg.Rate,
		interval: cfg.Interval,
		clock:    clock,
		keyOf:    keyOf,
		buckets:  map[string]*tokenBucket{},
	}
}

// systemClock is the production fallback when no Clock is injected.
type systemClock struct{}

// Now implements contracts.Clock.
func (systemClock) Now() time.Time { return time.Now() }

// sharedBucketKey is the bucket a request with NO client identity lands in.
// It is a DOCUMENTED decision, not an accident: until client authentication
// ships (F5/BD-01), a keyless request is still throttled — globally, through
// this one bucket — because an unthrottled router is the worse failure. The
// choice is observable on GateInput.Meta ("<id>.bucket" = "shared"), never
// logged, and the F5 contract makes the per-key bucket the only mode.
const sharedBucketKey = "default"

// defaultKeyOf resolves the client key: the boundary-supplied Meta key wins,
// then the resolved credential, then the shared bucket. None of these values
// is ever logged.
func defaultKeyOf(in contracts.GateInput) string {
	if in.Meta != nil {
		if k := in.Meta[MetaKeyClient]; k != "" {
			return k
		}
	}
	if in.Credential != "" {
		return string(in.Credential)
	}
	return sharedBucketKey
}

// ID implements contracts.Gate.
func (g *RateLimiter) ID() string { return IDRateLimit }

// Stages implements contracts.Gate.
func (g *RateLimiter) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate.
func (g *RateLimiter) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate.
func (g *RateLimiter) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }

// Declare implements contracts.GateDeclarer. The limiter reads and writes no
// request data: it is pure admission control, ordered in the containment phase
// by the ID tie-break (ADR-SEC-04 §1.1).
func (g *RateLimiter) Declare() contracts.Declared {
	return contracts.Declared{Stages: g.Stages()}
}

// PreRequest implements contracts.Gate: refill, then take one token or refuse.
func (g *RateLimiter) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	key := g.keyOf(in)
	// Make the bucket choice observable (labels only, never the key value):
	// "shared" documents the keyless global throttle, "client" a keyed one.
	if key == sharedBucketKey {
		setMeta(in.Meta, IDRateLimit+".bucket", "shared")
	} else {
		setMeta(in.Meta, IDRateLimit+".bucket", "client")
	}

	g.mu.Lock()
	now := g.clock.Now()
	b, ok := g.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: float64(g.rate), last: now}
		g.buckets[key] = b
	} else if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() / g.interval.Seconds() * float64(g.rate)
		if b.tokens > float64(g.rate) {
			b.tokens = float64(g.rate)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		g.mu.Unlock()
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	// Time until one token refills, scaled from the measured refill rate.
	wait := time.Duration((1 - b.tokens) / float64(g.rate) * float64(g.interval))
	g.mu.Unlock()

	retryAfter := int(math.Ceil(wait.Seconds()))
	d := blockWith(domain.CodeSecurityRateLimited,
		map[string]string{"retry_after": itoa(retryAfter)},
		http.StatusTooManyRequests)
	d.Synthetic.Headers.Set("Retry-After", itoa(retryAfter))
	return d, nil
}

// OnResponseChunk implements contracts.Gate: no post-commit action.
func (g *RateLimiter) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate: nothing to observe.
func (g *RateLimiter) PostResponse(context.Context, contracts.GateInput) error { return nil }

// Close implements contracts.Gate: buckets are in-memory only; nothing to
// release.
func (g *RateLimiter) Close() error { return nil }
