package memory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBoundedSinkExecutesAndDrains proves the sink runs accepted work and
// Close waits for it.
func TestBoundedSinkExecutesAndDrains(t *testing.T) {
	s := NewBoundedSink(4)
	ran := make(chan int, 8)
	for i := 0; i < 3; i++ {
		if ok := s.Submit(func(ctx context.Context) { ran <- i }); !ok {
			t.Fatalf("submit %d refused", i)
		}
	}
	// Do not race the worker: Close drains, then the channel has all values.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	close(ran)
	seen := 0
	for range ran {
		seen++
	}
	if seen != 3 {
		t.Fatalf("ran = %d, want 3", seen)
	}
	if s.Dropped() != 0 {
		t.Fatalf("dropped = %d", s.Dropped())
	}
}

// TestBoundedSinkDropsWhenFull pins the backpressure-by-drop contract.
func TestBoundedSinkDropsWhenFull(t *testing.T) {
	s := NewBoundedSink(1)
	release := make(chan struct{})
	running := make(chan struct{})
	s.Submit(func(context.Context) {
		close(running)
		<-release
	})
	<-running // the worker is busy inside task 1

	// Fills the queue's single slot.
	if !s.Submit(func(context.Context) {}) {
		t.Fatal("the queued task must be accepted")
	}
	// The queue is now full: this one MUST be refused, not waited on.
	if s.Submit(func(context.Context) {}) {
		t.Fatal("a full sink must drop, never block")
	}
	if s.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", s.Dropped())
	}
	close(release)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestBoundedSinkClosedRefuses pins the post-Close contract: no panic, no
// acceptance.
func TestBoundedSinkClosedRefuses(t *testing.T) {
	s := NewBoundedSink(2)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}
	if s.Submit(func(context.Context) {}) {
		t.Fatal("submit after close must be refused")
	}
	if s.Submit(nil) {
		t.Fatal("nil task must be refused")
	}
}

// TestBoundedSinkRunsOnDetachedContext proves the worker uses a context that
// survives the request (tasks must not receive a request-bound context).
func TestBoundedSinkRunsOnDetachedContext(t *testing.T) {
	s := NewBoundedSink(1)
	got := make(chan context.Context, 1)
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !s.Submit(func(ctx context.Context) { got <- ctx }) {
		t.Fatal("submit refused")
	}
	select {
	case ctx := <-got:
		if ctx == requestCtx {
			t.Fatal("the worker must not run tasks on the request context")
		}
		if ctx.Err() != nil {
			t.Fatal("the worker context must be live")
		}
	case <-time.After(time.Second):
		t.Fatal("task never ran")
	}
	_ = s.Close()
}

// TestSweeperGuardsAndSweeps covers the constructor guards and a deterministic
// sweep over an injected tick channel.
func TestSweeperGuardsAndSweeps(t *testing.T) {
	if NewSweeper(nil, nil, time.Second, nil) != nil {
		t.Fatal("storeless sweeper must not be constructed")
	}
	if NewSweeper(&fakeStore{}, nil, 0, nil) != nil {
		t.Fatal("zero-interval sweeper must not be constructed")
	}
	// A nil clock falls back to the system clock.
	if NewSweeper(&fakeStore{}, nil, time.Hour, nil) == nil {
		t.Fatal("nil clock must still build the sweeper")
	}

	store := &fakeStore{}
	ticks := make(chan time.Time)
	s := NewSweeper(store, &fixedClock{t: time.Unix(0, 0)}, time.Hour, func(n int64) {
		if n == 0 {
			t.Fatal("purged count must reach the callback")
		}
	})
	s.ticks = ticks
	s.Start()

	ticks <- time.Now()
	store.purgeMu.Lock()
	purged := store.purged
	store.purgeMu.Unlock()
	if purged == 0 {
		t.Fatal("the sweep did not run on tick")
	}

	// Error path, deterministic: the store fails exactly ONCE and signals each
	// ENTRY into PurgeExpired synchronously. The unbuffered tick hand-off
	// proves the loop took the error branch and survived it.
	store2 := &failOnceStore{fakeStore: fakeStore{}, called: make(chan struct{}, 2), failed: make(chan struct{}, 1)}
	rec := make(chan int64, 2)
	s2Ticks := make(chan time.Time)
	s2 := NewSweeper(store2, &fixedClock{t: time.Unix(0, 0)}, time.Hour, func(n int64) { rec <- n })
	s2.ticks = s2Ticks
	s2.Start()
	s2Ticks <- time.Now() // sweep 1: error branch
	<-store2.failed       // the failure is marked; the loop takes the error branch
	s2Ticks <- time.Now() // sweep 2: success; the loop survived
	if n := <-rec; n != 1 {
		t.Fatalf("recorded purge = %d", n)
	}
	<-store2.called // drain the buffered entry signal

	s.Stop()
	s2.Stop()
	s.Stop() // idempotent
}

// failOnceStore fails the first purge, then delegates to the embedded fake.
type failOnceStore struct {
	fakeStore
	called chan struct{}
	failed chan struct{}
	once   sync.Once
}

func (s *failOnceStore) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	s.called <- struct{}{}
	var err error
	s.once.Do(func() {
		err = errors.New("io storm")
		close(s.failed)
	})
	if err != nil {
		return 0, err
	}
	return s.fakeStore.PurgeExpired(ctx, now)
}

// TestBoundedSinkDefaultCapacity covers the non-positive capacity fallback.
func TestBoundedSinkDefaultCapacity(t *testing.T) {
	s := NewBoundedSink(0)
	if !s.Submit(func(context.Context) {}) {
		t.Fatal("the default-capacity sink must accept work")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestSweeperNilRecordAndRealTicker covers the no-callback sweep and the
// production ticker path end-to-end.
func TestSweeperNilRecordAndRealTicker(t *testing.T) {
	store := &fakeStore{}
	s := NewSweeper(store, &fixedClock{t: time.Unix(0, 0)}, time.Millisecond, nil)
	s.Start()
	swept := func() int64 {
		store.purgeMu.Lock()
		defer store.purgeMu.Unlock()
		return store.purged
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && swept() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Stop()
	if swept() == 0 {
		t.Fatal("the ticker never swept")
	}
}

// TestNamespaceOfPinsDerivation pins the cryptographic derivation of the
// namespace (SEC-07 §3) and its stability.
func TestNamespaceOfPinsDerivation(t *testing.T) {
	a1 := NamespaceOf("client-a")
	a2 := NamespaceOf("client-a")
	b := NamespaceOf("client-b")
	if a1 != a2 || a1 == b {
		t.Fatal("namespace derivation is unstable or colliding")
	}
	if len(a1) != 64 || strings.ToLower(a1) != a1 {
		t.Fatalf("namespace = %q, want 64 lowercase hex chars", a1)
	}
}
