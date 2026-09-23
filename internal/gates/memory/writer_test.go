package memory

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// realStoreFixture opens a throwaway vault and returns the real memory store.
func realStoreFixture(t *testing.T) MemoryStore {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return store.NewMemoryStore(s)
}

// writerFixture builds a writer with the given store and sink.
func writerFixture(st MemoryStore, sink contracts.AsyncSink, mutate func(*Config)) *MemoryWriter {
	cfg := Config{Store: st, Clock: &fixedClock{t: time.Unix(0, 0)}, Sink: sink}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewWriter(cfg)
}

func TestNewWriterGuards(t *testing.T) {
	if NewWriter(Config{}) != nil {
		t.Fatal("storeless writer must not be constructed")
	}
	if NewWriter(Config{Disabled: true, Store: &fakeStore{}}) != nil {
		t.Fatal("disabled writer must not be constructed")
	}
	w := NewWriter(Config{Store: &fakeStore{}})
	if w == nil {
		t.Fatal("wired writer must be constructed")
	}
	if w.ownedSink == nil {
		t.Fatal("a writer without an injected sink must own a BoundedSink")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestWriterStoresRedactedTurn is the core privacy assertion: the stored
// content is the CENTRAL-REDACTED text, the provenance/turn/TTL metadata is
// complete, and PostResponse itself never touches the store.
func TestWriterStoresRedactedTurn(t *testing.T) {
	st := &fakeStore{}
	sink := &trackingSink{}
	g := writerFixture(st, sink, nil)

	body := []byte(`{"messages":[{"role":"user","content":"my token is refresh_token abc123def456, remember the deploy window"}]}`)
	in := contracts.GateInput{RequestID: "req-77", Body: body, Meta: map[string]string{MetaKeyClient: "client-a"}}
	if err := g.PostResponse(context.Background(), in); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	if len(sink.tasks) != 1 {
		t.Fatalf("tasks = %d, want 1 (enqueued, not executed)", len(sink.tasks))
	}
	if st.insertCalls != 0 {
		t.Fatal("PostResponse must not write synchronously")
	}

	sink.drain()
	if st.insertCalls != 1 {
		t.Fatalf("inserts = %d, want 1 after drain", st.insertCalls)
	}
	got := st.inserted[0]
	wantNS := NamespaceOf("client-a")
	if got.Namespace != wantNS {
		t.Fatalf("namespace = %q", got.Namespace)
	}
	if strings.Contains(got.Content, "abc123def456") {
		t.Fatalf("secret survived redaction: %q", got.Content)
	}
	if !strings.Contains(got.Content, "[REDACTED]") || !strings.Contains(got.Content, "deploy window") {
		t.Fatalf("content = %q", got.Content)
	}
	if got.Provenance != contracts.SourceUser {
		t.Fatalf("provenance = %v", got.Provenance)
	}
	if got.TurnID != "req-77" {
		t.Fatalf("turn = %q", got.TurnID)
	}
	if got.ContentHash != contentHash(wantNS, "my token is refresh_token abc123def456, remember the deploy window") {
		t.Fatalf("content hash is not the hash of the ORIGINAL text: %q", got.ContentHash)
	}
	if got.ID == "" {
		t.Fatal("record must carry an id")
	}
	if !got.CreatedAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("created_at = %v (must come from the clock)", got.CreatedAt)
	}
	if got.ExpiresAt != got.CreatedAt.Add(DefaultTTL) {
		t.Fatalf("expires_at = %v, want created+TTL", got.ExpiresAt)
	}
}

// TestWriterDedupIdempotentByHash uses the REAL store: posting the same turn
// twice stores exactly one memory, and a different turn of the same client
// stores a second one.
func TestWriterDedupIdempotentByHash(t *testing.T) {
	real := realStoreFixture(t).(*store.MemoryStore)
	st := MemoryStore(real)
	sink := &trackingSink{}
	g := writerFixture(st, sink, nil)
	ctx := context.Background()

	post := func(text string) {
		in := contracts.GateInput{RequestID: "req", Body: chatBody(text), Meta: map[string]string{MetaKeyClient: "client-a"}}
		if err := g.PostResponse(ctx, in); err != nil {
			t.Fatalf("PostResponse: %v", err)
		}
		sink.drain()
	}
	post("the deploy window is tuesday")
	post("the deploy window is tuesday")
	ns := NamespaceOf("client-a")
	if n, err := real.CountNamespace(ctx, ns); err != nil || n != 1 {
		t.Fatalf("count = %d, %v; re-delivery must not duplicate", n, err)
	}
	post("a different fact")
	if n, _ := real.CountNamespace(ctx, ns); n != 2 {
		t.Fatalf("count after distinct fact = %d, want 2", n)
	}
}

// TestWriterNamespaceIsolation proves at gate level that two clients never
// share a row.
func TestWriterNamespaceIsolation(t *testing.T) {
	real := realStoreFixture(t).(*store.MemoryStore)
	sink := &trackingSink{}
	g := writerFixture(MemoryStore(real), sink, nil)
	ctx := context.Background()

	for _, key := range []string{"client-a", "client-b"} {
		in := contracts.GateInput{RequestID: "req", Body: chatBody("identical text"), Meta: map[string]string{MetaKeyClient: key}}
		if err := g.PostResponse(ctx, in); err != nil {
			t.Fatalf("PostResponse %s: %v", key, err)
		}
		sink.drain()
	}
	a, _ := real.CountNamespace(ctx, NamespaceOf("client-a"))
	b, _ := real.CountNamespace(ctx, NamespaceOf("client-b"))
	if a != 1 || b != 1 {
		t.Fatalf("counts a=%d b=%d, want 1/1 (identical content, distinct namespaces)", a, b)
	}
}

// TestWriterInertWithoutClientKey covers the mandatory-namespace inertness and
// the no-user-turn path.
func TestWriterInertWithoutClientKey(t *testing.T) {
	st := &fakeStore{}
	sink := &trackingSink{}
	g := writerFixture(st, sink, nil)

	if err := g.PostResponse(context.Background(), contracts.GateInput{Body: chatBody("hello")}); err != nil {
		t.Fatalf("no meta: %v", err)
	}
	if len(sink.tasks) != 0 {
		t.Fatal("no client key: nothing may be enqueued")
	}
	if err := g.PostResponse(context.Background(), contracts.GateInput{Meta: map[string]string{MetaKeyClient: "k"}}); err != nil {
		t.Fatalf("no body: %v", err)
	}
	if len(sink.tasks) != 0 {
		t.Fatal("no body: nothing may be enqueued")
	}
}

// TestWriterEmbedderOptIn proves the vector path: with an embedder the record
// carries its vector; with a failing embedder the memory is still stored and
// the failure is only counted.
func TestWriterEmbedderOptIn(t *testing.T) {
	st := &fakeStore{}
	sink := &trackingSink{}
	events := []string{}
	embed := &stubEmbedder{vec: []float32{1, 2}}
	g := writerFixture(st, sink, func(c *Config) {
		c.Embedder = embed
		c.Record = func(kind string) { events = append(events, kind) }
	})
	in := contracts.GateInput{RequestID: "r", Body: chatBody("remember this"), Meta: map[string]string{MetaKeyClient: "k"}}
	if err := g.PostResponse(context.Background(), in); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	sink.drain()
	if st.inserted[0].Embedding == nil {
		t.Fatal("embedding missing on the record")
	}

	// Failing embedder: the memory still lands, the error is counted.
	embed.err = errors.New("embedder down")
	sink2 := &trackingSink{}
	events = nil
	g2 := writerFixture(st, sink2, func(c *Config) {
		c.Embedder = embed
		c.Record = func(kind string) { events = append(events, kind) }
	})
	if err := g2.PostResponse(context.Background(), in); err != nil {
		t.Fatalf("PostResponse with failing embedder: %v", err)
	}
	sink2.drain()
	if len(st.inserted) != 2 {
		t.Fatalf("inserts = %d, want 2 (embed failure must not drop the memory)", len(st.inserted))
	}
	if st.inserted[1].Embedding != nil {
		t.Fatal("a failed embed must leave the vector nil")
	}
	if len(events) != 1 || events[0] != "embed_error" {
		t.Fatalf("events = %v, want [embed_error]", events)
	}
}

// TestWriterBackpressureDropsAndNeverBlocks is the AsyncSink contract proof:
// a refusing sink means a counted drop and an unchanged (nil) PostResponse.
func TestWriterBackpressureDropsAndNeverBlocks(t *testing.T) {
	st := &fakeStore{}
	sink := &trackingSink{closed: false}
	events := []string{}
	g := writerFixture(st, sink, func(c *Config) {
		c.Record = func(kind string) { events = append(events, kind) }
	})
	// Refuse the next submission.
	sink.closed = true
	err := g.PostResponse(context.Background(), contracts.GateInput{RequestID: "r", Body: chatBody("hi"), Meta: map[string]string{MetaKeyClient: "k"}})
	if err != nil {
		t.Fatalf("PostResponse must never surface sink backpressure: %v", err)
	}
	if len(events) != 1 || events[0] != "dropped" {
		t.Fatalf("events = %v, want [dropped]", events)
	}
}

// TestWriterInsertErrorCounted routes an insert failure through the record
// callback while PostResponse stays nil.
func TestWriterInsertErrorCounted(t *testing.T) {
	st := &fakeStore{insertErr: errors.New("disk gone")}
	sink := &trackingSink{}
	events := []string{}
	g := writerFixture(st, sink, func(c *Config) {
		c.Record = func(kind string) { events = append(events, kind) }
	})
	if err := g.PostResponse(context.Background(), contracts.GateInput{RequestID: "r", Body: chatBody("hi"), Meta: map[string]string{MetaKeyClient: "k"}}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	sink.drain()
	if len(events) != 1 || events[0] != "insert_error" {
		t.Fatalf("events = %v, want [insert_error]", events)
	}
}

// TestWriterCloseOwnership pins the sink lifecycle: an owned sink is closed by
// the gate; an injected one is not.
func TestWriterCloseOwnership(t *testing.T) {
	w := NewWriter(Config{Store: &fakeStore{}, Clock: &fixedClock{}})
	if w.ownedSink == nil {
		t.Fatal("expected an owned sink")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !w.ownedSink.closed {
		t.Fatal("owned sink must be closed by the gate")
	}
	if err := w.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}

	injected := &trackingSink{}
	w2 := writerFixture(&fakeStore{}, injected, nil)
	if w2.ownedSink != nil {
		t.Fatal("injected sink must not be owned")
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if injected.closed {
		t.Fatal("the gate must not close an injected sink")
	}
}

// TestWriterContractSurface pins the frozen-contract plumbing.
func TestWriterContractSurface(t *testing.T) {
	g := writerFixture(&fakeStore{}, &trackingSink{}, nil)
	if g.ID() != IDMemoryWriter {
		t.Fatalf("id = %s", g.ID())
	}
	if g.Stages() != contracts.StageSet(contracts.StagePostResponse) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailOpen {
		t.Fatal("writer is post-response: always FailOpen")
	}
	if !g.NeedsBody() {
		t.Fatal("writer must declare NeedsBody")
	}
	d := g.Declare()
	if len(d.Reads) != 0 || len(d.Writes) != 0 {
		t.Fatalf("declaration = %+v, want zero edges", d)
	}
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("PreRequest (never called by the pipeline): %v %v", dec, err)
	}
	chunk, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{})
	if err != nil || chunk.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk: %v %v", chunk, err)
	}
}

// blockingStore blocks inside Insert until released, so the owned sink's
// worker stays busy and the queue bound becomes observable.
type blockingStore struct {
	MemoryStore
	started chan struct{}
	release chan struct{}
}

func (s *blockingStore) Insert(ctx context.Context, r contracts.MemoryRecord) (bool, error) {
	s.started <- struct{}{} // the worker entered this task
	<-s.release
	return s.MemoryStore.Insert(ctx, r)
}

// TestWriterSinkCapacityAppliesToOwnedSink pins the Config.SinkCapacity knob:
// an owned sink honours the configured queue bound (capacity 1 → the third
// undrained write is dropped, never waited on).
func TestWriterSinkCapacityAppliesToOwnedSink(t *testing.T) {
	base := &fakeStore{}
	started := make(chan struct{}, 8) // buffered: drained tasks also signal
	release := make(chan struct{})
	st := &blockingStore{MemoryStore: base, started: started, release: release}
	events := make(chan string, 8)
	g := NewWriter(Config{
		Store:        st,
		Clock:        &fixedClock{t: time.Unix(0, 0)},
		SinkCapacity: 1,
		Record:       func(kind string) { events <- kind },
	})
	if g.ownedSink == nil {
		t.Fatal("expected an owned sink")
	}
	ctx := context.Background()
	post := func() {
		if err := g.PostResponse(ctx, contracts.GateInput{
			RequestID: "r", Body: chatBody("remember something"), Meta: map[string]string{MetaKeyClient: "k"},
		}); err != nil {
			t.Fatalf("PostResponse: %v", err)
		}
	}

	post()    // task 1: submitted
	<-started // deterministically: the worker is now blocked inside Insert
	post()    // task 2: fills the single queue slot
	post()    // task 3: the queue is full → dropped

	select {
	case kind := <-events:
		if kind != "dropped" {
			t.Fatalf("event = %q, want dropped", kind)
		}
	default:
		t.Fatal("the third write must be dropped synchronously (never queued)")
	}
	if got := g.ownedSink.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}

	close(release) // unblock the worker; the queue drains
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(base.inserted) != 2 {
		t.Fatalf("inserted = %d, want 2 (worker task + queued task)", len(base.inserted))
	}
}
