// Package memory holds the F4 wave-3 context-memory gates (ADR-SEC-07): the
// SYNCHRONOUS retriever (PreRequest, FailOpen) and the ASYNCHRONOUS writer
// (PostResponse, off the response path via contracts.AsyncSink).
//
// # Two units, one normative split (SEC-07 §1)
//
//   - MemoryRetriever searches the local store for memories relevant to the
//     last user turn and injects them into the prompt BEFORE the token engine
//     compresses it. It declares Writes [context], which is exactly the DAG
//     edge that orders the token gate after it (ADR-SEC-04 §1.3→§1.4), and it
//     declares Reads [cache_lookup], the forward-safe edge that will order it
//     after the semantic cache when that gate lands. FailOpen: a store error,
//     a timeout over the retrieval budget or an unusable body logs and
//     CONTINUES — retrieval is enrichment, never a gate the request must pass.
//   - MemoryWriter extracts the last user turn AFTER the exchange and hands it
//     to a bounded AsyncSink; the response path never waits for storage, and
//     an overflowing queue is backpressure by dropping. PostResponse is
//     FailOpen by contract (ADR-0014 §2).
//
// # Namespace isolation is mandatory (SEC-07 §3)
//
// The namespace is sha256(clientKey). A gate with no identifiable client key
// (Meta["client.key"], the same reserved boundary key the security family
// uses) is INERT: it neither retrieves nor stores, because a shared namespace
// would be a cross-client leak. Every store statement carries the namespace
// predicate.
//
// # Memory is DATA, never instructions (SEC-07 §2, anti-poisoning)
//
// Retrieved memories are injected delimited by <retrieved_memory provenance=…>
// tags under an explicit preamble stating they are consultative historical
// facts with no directive authority — never as system messages, and the
// retriever's own decision is Continue/Modify regardless of what the content
// says: no text, stored or inline, can flip a gate decision (ADR-SEC-03 §3).
//
// # Privacy (SEC-07 §4/§5)
//
// Every stored entry has a TTL (no memory is perennial); the writer redacts
// content through the central redactor BEFORE persistence; the embedder port
// defaults to OFF (local-first, FTS5-only retrieval — the modernc driver has
// no vec0 module, a documented roadmap gap) and the opt-in HTTP engine
// redacts before egress; the right to erasure is the store's
// PurgeNamespace, wired to the Management API in a later phase.
package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// The stable gate identifiers — also the per-gate feature-flag names
// (features.gates.<id>) and the Meta namespaces ("<id>.<key>").
const (
	// IDMemoryRetriever is the PreRequest gate.
	IDMemoryRetriever = "memory-retriever"
	// IDMemoryWriter is the PostResponse gate.
	IDMemoryWriter = "memory-writer"
)

// MetaKeyClient is the reserved GateInput.Meta key the HTTP boundary may set
// to identify the downstream client (mirrors the security family's key). The
// namespace is derived from it; its VALUE is never logged or stored.
const MetaKeyClient = "client.key"

// MemoryStore is the consumer-defined persistence port of the gates
// (interfaces are defined by the consumer; internal/store.MemoryStore
// satisfies it structurally).
type MemoryStore interface {
	// Insert stores one record; inserted is false when the (namespace,
	// content) already existed — the dedup is the store's idempotency.
	Insert(ctx context.Context, rec contracts.MemoryRecord) (bool, error)
	// Search returns at most limit lexical hits for ONE namespace, never
	// expired ones, best first.
	Search(ctx context.Context, namespace, query string, now time.Time, limit int) ([]contracts.MemoryHit, error)
	// PurgeExpired removes expired rows (the TTL sweep).
	PurgeExpired(ctx context.Context, now time.Time) (int64, error)
	// PurgeNamespace removes every row of one namespace (erasure right).
	PurgeNamespace(ctx context.Context, namespace string) (int64, error)
}

// Config configures both gates. The zero value builds nothing: Disabled gates
// are never constructed (ADR-0014 §4), and a nil Store would silently break
// the mandatory-namespace contract.
type Config struct {
	// Disabled switches the whole family off (both constructors return nil).
	Disabled bool
	// Store is the persistence port. Required for both gates.
	Store MemoryStore
	// Clock is the injected time source (TTL, sweep, IDs). Nil → system clock.
	Clock contracts.Clock
	// KeyOf derives the client key from the gate input. Nil → the reserved
	// Meta["client.key"]; an empty key makes the gates INERT (no namespace,
	// no memory — never a shared namespace).
	KeyOf func(contracts.GateInput) string
	// TTL is the retention of a stored memory. Zero → DefaultTTL.
	TTL time.Duration
	// RetrievalLimit caps the injected memories. Zero → DefaultRetrievalLimit.
	RetrievalLimit int
	// Budget bounds ONE retrieval call. Zero → DefaultBudget (SEC-07 §1:
	// 100ms).
	Budget time.Duration
	// MaxContent bounds the extracted/stored text in bytes. Zero → default.
	MaxContent int
	// Embedder is the optional vector engine. Nil → vector mode OFF
	// (local-first; FTS5-only retrieval until a vec0-capable driver lands).
	Embedder contracts.Embedder
	// Sink receives the writer's async work. Nil → the writer owns a
	// BoundedSink with SinkCapacity (and closes it on Close).
	Sink contracts.AsyncSink
	// SinkCapacity is the owned-sink queue bound: the number of pending
	// memory writes before backpressure starts DROPPING them. Zero →
	// DefaultSinkCapacity. Ignored when Sink is injected (the owner sets its
	// own bound).
	SinkCapacity int
	// Record receives observability events (kinds only, never content). Nil is
	// a no-op.
	Record func(kind string)
}

// Defaults (ADR-SEC-07): episodic retention, a bounded retrieval, and a sink
// queue that absorbs bursts without ever blocking the response.
const (
	// DefaultTTL is the episodic retention (§4: 30 days).
	DefaultTTL = 30 * 24 * time.Hour
	// DefaultRetrievalLimit caps the injected hits.
	DefaultRetrievalLimit = 3
	// DefaultBudget is the synchronous retrieval budget (§1: 100 ms).
	DefaultBudget = 100 * time.Millisecond
	// DefaultMaxContent bounds one extracted/stored text.
	DefaultMaxContent = 4096
	// DefaultSinkCapacity is the writer queue bound (backpressure by drop).
	DefaultSinkCapacity = 64
)

// systemClock is the production fallback when no Clock is injected.
type systemClock struct{}

// Now implements contracts.Clock.
func (systemClock) Now() time.Time { return time.Now() }

// settings is the normalised, read-only view both gates share.
type settings struct {
	store    MemoryStore
	clock    contracts.Clock
	keyOf    func(contracts.GateInput) string
	ttl      time.Duration
	limit    int
	budget   time.Duration
	maxBody  int
	embedder contracts.Embedder
	record   func(kind string)
	sink     contracts.AsyncSink
	ownsSink bool
	sinkCap  int
}

// normalise fills the zero fields with the documented defaults.
func (c Config) normalise() settings {
	s := settings{
		store:    c.Store,
		clock:    c.Clock,
		keyOf:    c.KeyOf,
		ttl:      c.TTL,
		limit:    c.RetrievalLimit,
		budget:   c.Budget,
		maxBody:  c.MaxContent,
		embedder: c.Embedder,
		record:   c.Record,
		sink:     c.Sink,
		sinkCap:  c.SinkCapacity,
	}
	if s.clock == nil {
		s.clock = systemClock{}
	}
	if s.keyOf == nil {
		s.keyOf = defaultKeyOf
	}
	if s.ttl <= 0 {
		s.ttl = DefaultTTL
	}
	if s.limit <= 0 {
		s.limit = DefaultRetrievalLimit
	}
	if s.budget <= 0 {
		s.budget = DefaultBudget
	}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxContent
	}
	if s.sinkCap <= 0 {
		s.sinkCap = DefaultSinkCapacity
	}
	return s
}

// defaultKeyOf resolves the client key from the reserved Meta entry. An empty
// result makes the gates inert (SEC-07 §3: never a shared namespace).
func defaultKeyOf(in contracts.GateInput) string {
	if in.Meta == nil {
		return ""
	}
	return in.Meta[MetaKeyClient]
}

// NamespaceOf derives the storage namespace of a client key: the sha256 hex
// (ADR-SEC-07 §3 prescribes a cryptographic derivation).
func NamespaceOf(clientKey string) string {
	sum := sha256.Sum256([]byte(clientKey))
	return hex.EncodeToString(sum[:])
}

// memoryID builds the time-ordered, deterministic identifier of a record:
// millisecond timestamp + a short hash of the content hash. The storage dedup
// makes any residual collision harmless (the second insert is a no-op).
func memoryID(now time.Time, contentHash string) string {
	short := contentHash
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%013d-%s", now.UnixMilli(), short)
}

// hashOf is the sha256 hex used for namespaces and content hashes.
func hashOf(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// contentHash is the dedup key of a record: sha256(namespace || content).
func contentHash(namespace, content string) string {
	return hashOf(namespace, content)
}
