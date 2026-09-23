package contracts

import (
	"context"
	"time"
)

// This file holds the ADDITIVE memory ports and value types of F4 wave 3
// (ADR-SEC-07). Nothing here changes a frozen contract: the memory gates
// (internal/gates/memory) and the persistence (internal/store) consume these
// ports, and every type crossing them is a plain value, in line with the
// package's boundary philosophy.

// MemoryProvenance is the origin of a stored memory (ADR-SEC-07 §2). It is
// audit metadata: retrieved memories are DATA with a declared origin, never
// system instructions.
type MemoryProvenance uint8

const (
	// SourceUser marks content extracted from a downstream user turn.
	SourceUser MemoryProvenance = iota
	// SourceAssistant marks content extracted from an assistant turn.
	SourceAssistant
	// SourceSystem marks operator- or pipeline-authored content.
	SourceSystem
)

// String renders the provenance deterministically.
func (p MemoryProvenance) String() string {
	switch p {
	case SourceUser:
		return "user"
	case SourceAssistant:
		return "assistant"
	case SourceSystem:
		return "system"
	default:
		return "unknown"
	}
}

// MemoryRecord is one durable memory entry (ADR-SEC-07 §2). Namespace is
// MANDATORY: the sha256 of the client identity, so isolation between clients
// is enforced at the storage layer. Content arrives already redacted; the
// writer's contract requires it and the store trusts nothing beyond that.
type MemoryRecord struct {
	// ID is a time-ordered identifier (timestamp-derived, deterministic from
	// the creation instant plus the content hash).
	ID string
	// Namespace is the sha256 hex of the client key (ADR-SEC-07 §3).
	Namespace string
	// Content is the redacted memory text.
	Content string
	// Embedding is the optional vector (nil when the vector mode is off).
	Embedding []float32
	// Provenance is the declared origin of the content.
	Provenance MemoryProvenance
	// TurnID correlates the entry with the request that produced it.
	TurnID string
	// ContentHash is the dedup key: sha256(namespace || content), so a
	// re-delivered memory is idempotent (ADR-SEC-07 §2).
	ContentHash string
	// CreatedAt is the (injected-clock) creation instant, UTC.
	CreatedAt time.Time
	// ExpiresAt is the TTL horizon; expired rows are invisible and purged.
	ExpiresAt time.Time
}

// MemoryHit is one retrieval result. It carries the audit metadata the
// anti-poisoning delimiters render into the prompt (provenance, turn, age) and
// the storage rank position.
type MemoryHit struct {
	ID         string
	Content    string
	Provenance MemoryProvenance
	TurnID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	// Rank is the 0-based position in the store's ordering (best first).
	Rank int
}

// AsyncSink accepts work that must run OUT of the response path (ADR-SEC-07
// §1). Implementations must be non-blocking for the producer: a full queue is
// BACKPRESSURE BY DROPPING — the caller is told false and the response path
// never waits for storage. Submit must be safe for concurrent use.
type AsyncSink interface {
	// Submit enqueues task without executing it. false means the queue was
	// full (or the sink is closed) and the task was dropped.
	Submit(task func(context.Context)) bool
	// Close stops accepting work and drains what was already accepted. It is
	// idempotent.
	Close() error
}

// Embedder produces vectors for memory content (ADR-SEC-07 §5). It is a PORT:
// the local-first default is "no embedder" (vector mode off, FTS5 only); an
// external embedding API is an explicit operator opt-in whose implementation
// MUST redact/pseudonymize content before any egress.
type Embedder interface {
	// ID names the engine (diagnostics only, never content).
	ID() string
	// Dim is the vector dimensionality the engine produces.
	Dim() int
	// Embed returns the vector for one content string.
	Embed(ctx context.Context, content string) ([]float32, error)
}
