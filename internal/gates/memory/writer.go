package memory

import (
	"context"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// MemoryWriter is the ASYNCHRONOUS PostResponse memory gate (ADR-SEC-07 §1):
// it extracts the last user turn AFTER the exchange, redacts it through the
// CENTRAL redactor (SEC-07 §5 — nothing sensitive ever reaches the disk), and
// hands it to a bounded AsyncSink. The response path performs no I/O: Submit
// is non-blocking and a full queue is backpressure by dropping (counted, never
// waited on).
//
// Idempotency: the record carries sha256(namespace||content) and the store's
// UNIQUE constraint turns a re-delivery into a no-op, so a retried or repeated
// post-response never duplicates a memory.
//
// The gate is PostResponse-only, and PostResponse is FailOpen by contract
// (ADR-0014 §2).
type MemoryWriter struct {
	cfg       settings
	ownedSink *BoundedSink // non-nil when the writer created its own sink
}

// Compile-time assertions.
var (
	_ contracts.Gate         = (*MemoryWriter)(nil)
	_ contracts.GateDeclarer = (*MemoryWriter)(nil)
	_ contracts.BodyConsumer = (*MemoryWriter)(nil)
)

// NewWriter builds the gate, or nil when disabled or unwired. A nil Sink
// creates an OWNED BoundedSink (DefaultSinkCapacity) that Close() drains; an
// injected sink belongs to the wiring and is never closed by the gate.
func NewWriter(cfg Config) *MemoryWriter {
	if cfg.Disabled || cfg.Store == nil {
		return nil
	}
	s := cfg.normalise()
	w := &MemoryWriter{cfg: s}
	if s.sink == nil {
		w.ownedSink = NewBoundedSink(s.sinkCap)
		w.cfg.sink = w.ownedSink
		w.cfg.ownsSink = true
	}
	return w
}

// ID implements contracts.Gate.
func (g *MemoryWriter) ID() string { return IDMemoryWriter }

// Stages implements contracts.Gate: persistence runs strictly post-response.
func (g *MemoryWriter) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePostResponse)
}

// RequiredCaps implements contracts.Gate.
func (g *MemoryWriter) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate. PostResponse is always FailOpen
// (ADR-0014 §2); the registry refuses the opposite combination.
func (g *MemoryWriter) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }

// NeedsBody implements contracts.BodyConsumer: the stored turn comes from the
// request body.
func (g *MemoryWriter) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. The writer observes no gate data
// field and writes none — it feeds the STORE, not the request — so it has no
// graph edge and is ordered by ID inside its stage.
func (g *MemoryWriter) Declare() contracts.Declared {
	return contracts.Declared{Stages: g.Stages()}
}

// PostResponse implements contracts.Gate. It only extracts, redacts and
// enqueues — the store write happens on the sink's goroutine, and this method
// always returns nil (async failures are counted through Record).
func (g *MemoryWriter) PostResponse(_ context.Context, in contracts.GateInput) error {
	key := g.cfg.keyOf(in)
	if key == "" {
		// No identifiable client: no namespace, no memory (SEC-07 §3) — and
		// the skip is OBSERVABLE, not silent.
		setMeta(in.Meta, IDMemoryWriter+".skipped", "no-client-key")
		return nil
	}
	text := lastUserText(in.Body, g.cfg.maxBody)
	if text == "" {
		return nil
	}
	ns := NamespaceOf(key)
	now := g.cfg.clock.Now().UTC()
	rec := contracts.MemoryRecord{
		ID:          memoryID(now, contentHash(ns, text)),
		Namespace:   ns,
		Content:     i18n.RedactString(text),
		Provenance:  contracts.SourceUser,
		TurnID:      in.RequestID.String(),
		ContentHash: contentHash(ns, text),
		CreatedAt:   now,
		ExpiresAt:   now.Add(g.cfg.ttl),
	}
	if g.cfg.embedder != nil {
		// Vector mode is opt-in; the embedder itself redacts before any
		// egress (SEC-07 §5). An embedding failure NEVER fails the write.
		if vec, err := g.cfg.embedder.Embed(context.Background(), rec.Content); err == nil {
			rec.Embedding = vec
		} else if g.cfg.record != nil {
			g.cfg.record("embed_error")
		}
	}
	submitted := g.cfg.sink.Submit(func(ctx context.Context) {
		_, err := g.cfg.store.Insert(ctx, rec)
		if err != nil {
			g.record("insert_error")
			return
		}
	})
	if !submitted {
		g.record("dropped")
	}
	return nil
}

// record emits one observability kind (never content).
func (g *MemoryWriter) record(kind string) {
	if g.cfg.record != nil {
		g.cfg.record(kind)
	}
}

// PreRequest implements contracts.Gate. The writer declares ONLY the
// post-response stage, so the pipeline never calls this; the frozen interface
// still requires it, and a direct caller gets an explicit no-op rather than a
// panic.
func (g *MemoryWriter) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}

// OnResponseChunk implements contracts.Gate: the writer is not a chunk gate.
func (g *MemoryWriter) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// Close implements contracts.Gate: it drains the OWNED sink (if any) and
// leaves injected sinks to their owner.
func (g *MemoryWriter) Close() error {
	if g.ownedSink != nil {
		return g.ownedSink.Close()
	}
	return nil
}

// BoundedSink is the default contracts.AsyncSink: ONE worker goroutine drains
// a bounded queue; Submit never blocks (a full queue drops and counts), and
// Close drains what was accepted and is idempotent. Tasks run on a detached
// context (the request context dies with the client connection; a memory
// write must survive it).
type BoundedSink struct {
	tasks   chan func(context.Context)
	mu      sync.RWMutex
	closed  bool
	wg      sync.WaitGroup
	dropped int64
}

// NewBoundedSink starts the worker. A non-positive capacity falls back to the
// documented default.
func NewBoundedSink(capacity int) *BoundedSink {
	if capacity <= 0 {
		capacity = DefaultSinkCapacity
	}
	s := &BoundedSink{tasks: make(chan func(context.Context), capacity)}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx := context.Background()
		for task := range s.tasks {
			task(ctx)
		}
	}()
	return s
}

// Submit implements contracts.AsyncSink. It never blocks: when the queue is
// full the task is dropped, the drop is counted and false is returned.
func (s *BoundedSink) Submit(task func(context.Context)) bool {
	if task == nil {
		return false
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return false
	}
	s.mu.RUnlock()
	select {
	case s.tasks <- task:
		return true
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
		return false
	}
}

// Dropped returns how many tasks were refused for a full queue.
func (s *BoundedSink) Dropped() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropped
}

// Close implements contracts.AsyncSink: no new work is accepted and the
// accepted work drains before it returns. Idempotent.
func (s *BoundedSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	close(s.tasks)
	s.wg.Wait()
	return nil
}

var _ contracts.AsyncSink = (*BoundedSink)(nil)

// Sweeper periodically purges expired memories (ADR-SEC-07 §4): TTL is not
// optional, and Search hides expired rows even between sweeps — the sweep is
// the disk hygiene half. Start is non-blocking; Stop is idempotent and waits.
type Sweeper struct {
	store  MemoryStore
	clock  contracts.Clock
	every  time.Duration
	record func(int64)
	// ticks, when set, replaces the internal ticker (test seam for
	// deterministic sweeps).
	ticks <-chan time.Time
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// NewSweeper builds the periodic purge. A nil store or a non-positive
// interval returns nil — nothing to sweep is not a sweeper.
func NewSweeper(store MemoryStore, clock contracts.Clock, every time.Duration, record func(int64)) *Sweeper {
	if store == nil || every <= 0 {
		return nil
	}
	if clock == nil {
		clock = systemClock{}
	}
	return &Sweeper{
		store:  store,
		clock:  clock,
		every:  every,
		record: record,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start launches the loop.
func (s *Sweeper) Start() {
	go func() {
		defer close(s.done)
		var ticker *time.Ticker
		ticks := s.ticks
		if ticks == nil {
			ticker = time.NewTicker(s.every)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			select {
			case <-s.stop:
				return
			case <-ticks:
				n, err := s.store.PurgeExpired(context.Background(), s.clock.Now())
				if err != nil {
					continue // the sweep is hygiene; the next tick retries
				}
				if s.record != nil {
					s.record(n)
				}
			}
		}
	}()
}

// Stop terminates the loop and waits for it. Idempotent.
func (s *Sweeper) Stop() {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}
