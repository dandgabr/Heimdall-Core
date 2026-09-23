package security

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fixedClock is the deterministic time source (quota/breaker pattern).
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// TestRateLimiterBlocksAfterNAndReleasesAfterInterval is the required
// assertion: N requests pass, the N+1th gets a 429 Block with Retry-After,
// and after the interval the bucket refills and passes again.
func TestRateLimiterBlocksAfterNAndReleasesAfterInterval(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	g := NewRateLimit(RateLimitConfig{Rate: 2, Interval: time.Minute, Clock: clock})
	if g == nil {
		t.Fatal("gate must be constructed")
	}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		dec, err := g.PreRequest(ctx, contracts.GateInput{})
		if err != nil || dec.Kind != contracts.DecisionContinue {
			t.Fatalf("request %d: dec=%v err=%v", i, dec, err)
		}
	}

	dec, err := g.PreRequest(ctx, contracts.GateInput{})
	if err != nil {
		t.Fatalf("third request: %v", err)
	}
	if dec.Kind != contracts.DecisionBlock {
		t.Fatalf("third request kind = %v, want Block", dec.Kind)
	}
	if dec.Synthetic == nil || dec.Synthetic.Status != 429 {
		t.Fatalf("synthetic = %+v, want 429", dec.Synthetic)
	}
	if dec.Code != domain.CodeSecurityRateLimited {
		t.Fatalf("code = %s", dec.Code)
	}
	if got := dec.Params["retry_after"]; got != "30" {
		t.Fatalf("retry_after = %q, want 30 (time to the next token at 2/min)", got)
	}
	if got := dec.Synthetic.Headers.Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After header = %q", got)
	}
	var env envelope
	if err := json.Unmarshal(dec.Synthetic.Body, &env); err != nil {
		t.Fatalf("synthetic body: %v", err)
	}
	if env.Error.Code != domain.CodeSecurityRateLimited {
		t.Fatalf("envelope = %s", dec.Synthetic.Body)
	}

	// A partial refill is not enough: after 30s exactly 1 token refilled and
	// the request consumes it.
	clock.advance(30 * time.Second)
	dec, err = g.PreRequest(ctx, contracts.GateInput{})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("after half interval: dec=%v err=%v", dec, err)
	}
	// The next one is refused again (1 token was consumed, half a token left).
	dec, err = g.PreRequest(ctx, contracts.GateInput{})
	if err != nil || dec.Kind != contracts.DecisionBlock {
		t.Fatalf("after consuming refill: dec=%v err=%v", dec, err)
	}

	// A full interval refills the whole bucket.
	clock.advance(time.Minute)
	for i := 0; i < 2; i++ {
		dec, err = g.PreRequest(ctx, contracts.GateInput{})
		if err != nil || dec.Kind != contracts.DecisionContinue {
			t.Fatalf("after refill %d: dec=%v err=%v", i, dec, err)
		}
	}
}

// TestRateLimiterKeysAreIndependent proves per-client isolation: exhausting
// key A does not touch key B.
func TestRateLimiterKeysAreIndependent(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	g := NewRateLimit(RateLimitConfig{
		Rate:     1,
		Interval: time.Minute,
		Clock:    clock,
		KeyOf:    func(in contracts.GateInput) string { return in.Meta["client.key"] },
	})
	ctx := context.Background()
	allow := contracts.GateInput{Meta: map[string]string{"client.key": "a"}}
	other := contracts.GateInput{Meta: map[string]string{"client.key": "b"}}

	if dec, err := g.PreRequest(ctx, allow); err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("a#1: %v %v", dec, err)
	}
	if dec, _ := g.PreRequest(ctx, allow); dec.Kind != contracts.DecisionBlock {
		t.Fatalf("a#2 must block, got %v", dec.Kind)
	}
	if dec, err := g.PreRequest(ctx, other); err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("b#1: %v %v", dec, err)
	}
}

// TestDefaultKeyOf covers the fallback ladder: boundary Meta key, then
// credential, then the shared default bucket.
func TestDefaultKeyOf(t *testing.T) {
	if got := defaultKeyOf(contracts.GateInput{Meta: map[string]string{MetaKeyClient: "k1"}}); got != "k1" {
		t.Fatalf("meta key: %q", got)
	}
	if got := defaultKeyOf(contracts.GateInput{Meta: map[string]string{}, Credential: "cred-1"}); got != "cred-1" {
		t.Fatalf("credential: %q", got)
	}
	if got := defaultKeyOf(contracts.GateInput{}); got != "default" {
		t.Fatalf("default: %q", got)
	}
}

// TestRateLimiterCapAndClockRegression covers the capacity cap (refill never
// exceeds rate) and a clock that moves backwards (no negative refill).
func TestRateLimiterCapAndClockRegression(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	g := NewRateLimit(RateLimitConfig{Rate: 2, Interval: time.Second, Clock: clock})
	ctx := context.Background()

	// Consume one token, then jump far past several intervals: the bucket is
	// capped at rate, not inflated.
	if dec, _ := g.PreRequest(ctx, contracts.GateInput{}); dec.Kind != contracts.DecisionContinue {
		t.Fatal("first must pass")
	}
	clock.advance(10 * time.Second)
	if dec, _ := g.PreRequest(ctx, contracts.GateInput{}); dec.Kind != contracts.DecisionContinue {
		t.Fatal("second must pass (refilled)")
	}
	if dec, _ := g.PreRequest(ctx, contracts.GateInput{}); dec.Kind != contracts.DecisionContinue {
		t.Fatal("third must pass (capped at rate=2)")
	}
	if dec, _ := g.PreRequest(ctx, contracts.GateInput{}); dec.Kind != contracts.DecisionBlock {
		t.Fatal("fourth must block: the cap is the rate, not the elapsed time")
	}

	// Clock regression: elapsed <= 0 must not refill (the block above used the
	// last token; rewinding the clock must not mint tokens).
	clock.advance(-10 * time.Second)
	if dec, _ := g.PreRequest(ctx, contracts.GateInput{}); dec.Kind != contracts.DecisionBlock {
		t.Fatal("clock regression must not refill")
	}
}

// TestRateLimiterConcurrentIsSafe hammers the gate from parallel requests
// (race detector) and pins the admission count: exactly rate requests pass on
// a fixed clock, no matter the interleaving.
func TestRateLimiterConcurrentIsSafe(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	const rate = 8
	g := NewRateLimit(RateLimitConfig{Rate: rate, Interval: time.Hour, Clock: clock})

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	blocked := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dec, err := g.PreRequest(context.Background(), contracts.GateInput{})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("concurrent PreRequest: %v", err)
				return
			}
			switch dec.Kind {
			case contracts.DecisionContinue:
				allowed++
			case contracts.DecisionBlock:
				blocked++
			default:
				t.Errorf("unexpected kind %v", dec.Kind)
			}
		}()
	}
	wg.Wait()
	if allowed != rate || blocked != workers-rate {
		t.Fatalf("allowed=%d blocked=%d, want %d/%d", allowed, blocked, rate, workers-rate)
	}
}

// TestNewRateLimitGuardsAndContract covers the construction guards, the
// system-clock fallback, metadata and lifecycle.
func TestNewRateLimitGuardsAndContract(t *testing.T) {
	if NewRateLimit(RateLimitConfig{Rate: 0, Interval: time.Second}) != nil {
		t.Fatal("rate 0 must not construct")
	}
	if NewRateLimit(RateLimitConfig{Rate: 1, Interval: 0}) != nil {
		t.Fatal("interval 0 must not construct")
	}
	g := NewRateLimit(RateLimitConfig{Rate: 1, Interval: time.Second}) // nil Clock → system clock
	if g == nil {
		t.Fatal("nil clock must fall back to the system clock")
	}
	// One request through the system-clock path.
	if dec, err := g.PreRequest(context.Background(), contracts.GateInput{}); err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("system clock path: %v %v", dec, err)
	}
	if g.ID() != IDRateLimit {
		t.Fatalf("id = %s", g.ID())
	}
	if g.Stages() != contracts.StageSet(contracts.StagePreRequest) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailOpen {
		t.Fatal("rate limit is availability machinery: FailOpen")
	}
	if contracts.ConsumesBody(g) {
		t.Fatal("rate limit must NOT need the body")
	}
	d := g.Declare()
	if len(d.Reads) != 0 || len(d.Writes) != 0 {
		t.Fatalf("declaration = %+v, want zero edges", d)
	}
	chunk, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{})
	if err != nil || chunk.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk: %v %v", chunk, err)
	}
	if err := g.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("post: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestRateLimiterBucketChoiceIsObservable pins the G-1 explicit behaviour: a
// keyed request marks its bucket "client", a keyless one lands in the SHARED
// bucket with the choice recorded on Meta (labels only, never the key).
func TestRateLimiterBucketChoiceIsObservable(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	g := NewRateLimit(RateLimitConfig{Rate: 10, Interval: time.Minute, Clock: clock})
	ctx := context.Background()

	keyed := contracts.GateInput{Meta: map[string]string{MetaKeyClient: "client-a"}}
	if dec, err := g.PreRequest(ctx, keyed); err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("keyed: %v %v", dec, err)
	}
	if got := keyed.Meta[IDRateLimit+".bucket"]; got != "client" {
		t.Fatalf("keyed bucket label = %q, want client", got)
	}

	keyless := contracts.GateInput{Meta: map[string]string{}}
	if dec, err := g.PreRequest(ctx, keyless); err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("keyless: %v %v", dec, err)
	}
	if got := keyless.Meta[IDRateLimit+".bucket"]; got != "shared" {
		t.Fatalf("keyless bucket label = %q, want shared", got)
	}

	// The label is a decision mark, not a leak: it never carries the key.
	for k, v := range keyless.Meta {
		if strings.Contains(v, "client-a") {
			t.Fatalf("meta[%s] leaks the client key", k)
		}
	}
}
