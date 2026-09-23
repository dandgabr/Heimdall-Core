// Package token implements the TOKEN-ECONOMY gate of F4 (ADR-0015): a
// PreRequest gate that compresses the canonical prompt WITHOUT invalidating the
// upstream prompt cache.
//
// # Position in the graph
//
// The gate declares Reads{FieldContext, FieldCacheLookup} and
// Writes{FieldPromptText, FieldPrefixRange} (ADR-SEC-04 §1): the DAG therefore
// orders it AFTER the memory retriever (which writes `context`) and after the
// semantic-cache lookup (which writes `cache_lookup`) and before the security
// gates that read the final `prompt_text`.
//
// # The central invariant: prefix-freeze
//
// Providers reuse the IDENTICAL PREFIX of a repeated prompt at a fraction of the
// price. The gate computes the cacheable prefix boundary once per request and
// FREEZES it: every engine may only rewrite text OUTSIDE it, unless the engine
// declares ImpactHigh AND the operator opted in per engine (ADR-0015 §3).
// Rewriting the prefix can cost more than the tokens it saves, so the default
// posture is "do not touch the prefix".
//
// # Minimum content (ADR-SEC-03)
//
// The gate needs the body to compress it, so it implements
// contracts.BodyConsumer (NeedsBody) and the caller delivers Body only then. The
// gate NEVER logs or persists the body: it records COUNTS only (bytes/tokens),
// and even those go through the pipeline's metadata (no content).
package token

import "github.com/dandgabr/heimdall-core/internal/domain"

// CacheImpact qualifies an engine's effect on the upstream prompt cache. It is a
// DECLARATION by the engine, not inferred (ADR-0015 §1): whoever writes the
// engine knows what it touches, and the registry makes that declaration
// binding.
type CacheImpact uint8

const (
	// ImpactNone: the engine does not alter prompt text (e.g. it only counts, or
	// deduplicates PRESERVING order and prefix).
	ImpactNone CacheImpact = iota
	// ImpactLow: alters text only OUTSIDE the cacheable prefix, offset-preserving
	// (e.g. compressing the suffix).
	ImpactLow
	// ImpactModerate: alters the suffix in a way that can move the cache boundary
	// (a shifting delimiter), but never the frozen prefix.
	ImpactModerate
	// ImpactHigh: can alter the cacheable prefix itself. Runs ONLY with an
	// explicit per-engine opt-in (ADR-0015 §3).
	ImpactHigh
)

// String renders the impact for the boot audit log (ADR-0015 §1).
func (c CacheImpact) String() string {
	switch c {
	case ImpactNone:
		return "none"
	case ImpactLow:
		return "low"
	case ImpactModerate:
		return "moderate"
	case ImpactHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Stats is the per-request accounting an engine reports. It carries COUNTS and
// a boolean only: never prompt content, so it is safe to log (ADR-0015 §5,
// ADR-SEC-03 §2).
type Stats struct {
	// ID is the engine that produced the stats.
	ID string
	// BytesIn and BytesOut are the payload sizes before/after.
	BytesIn  int
	BytesOut int
	// TokensSaved is the engine's estimate of tokens removed (a heuristic; the
	// authoritative count is the provider's). It is observability, never a
	// security decision.
	TokensSaved int
	// PrefixInvalidated is true when the engine touched the frozen prefix (only
	// possible with ImpactHigh + opt-in, ADR-0015 §5).
	PrefixInvalidated bool
}

// Applied reports whether the engine actually changed the payload.
func (s Stats) Applied() bool { return s.BytesOut != s.BytesIn }

// Options carries the per-request inputs an engine may use. It is deliberately
// data-only (no context, no I/O) so engines stay PURE and testable: the same
// input always yields the same output.
type Options struct {
	// PrefixEnd is the exclusive end offset of the frozen cacheable prefix. Text
	// with offset < PrefixEnd MUST NOT be altered (absent opt-in). Zero means
	// "no stable prefix" (ADR-0015 §2): the whole prompt is suffix and may be
	// compressed.
	PrefixEnd int
	// AllowPrefixRewrite is the operator's per-engine opt-in (ADR-0015 §3). It
	// only ever matters for an ImpactHigh engine; a non-high engine must never
	// read the prefix regardless.
	AllowPrefixRewrite bool
	// Model is the requested model, for engines that key behaviour on it.
	Model domain.ModelID
}

// CompressionEngine is a PURE prompt-compression unit (ADR-0015 §1). Apply must
// not perform I/O, must not read a clock, and must be deterministic for the same
// input. It reports Stats (counts only) and never returns partial output on an
// error (the gate treats any error as FailOpen and keeps the original).
type CompressionEngine interface {
	// ID is the stable engine identifier, unique within the registry.
	ID() string
	// CacheImpact declares the engine's effect on the upstream prompt cache.
	CacheImpact() CacheImpact
	// Lossy reports whether the engine may discard information.
	Lossy() bool
	// Apply compresses canonical and returns the result plus stats. On error it
	// MUST return the input unchanged and zero stats (never a truncated body).
	Apply(canonical []byte, opts Options) (out []byte, stats Stats, err error)
}
