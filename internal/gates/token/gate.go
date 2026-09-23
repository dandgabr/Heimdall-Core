package token

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// Gate is the token-economy gate (ADR-0015). It acts in the PreRequest stage:
// it compresses the canonical prompt BEFORE the dispatch, respecting the frozen
// cacheable prefix, and returns a DecisionModify with the compressed body.
//
// # Prefix-freeze enforcement
//
// The gate computes the cacheable prefix boundary once per request and passes it
// to every engine as Options.PrefixEnd. It then VERIFIES the engine's output:
// unless the engine is ImpactHigh AND the operator opted in, the frozen prefix
// of the output MUST byte-equal the input's. If an engine violates the freeze,
// that engine's change is DISCARDED (the body reverts to that engine's input) —
// the gate fails safe, because invalidating the cache can cost more than the
// tokens saved.
//
// # FailurePolicy
//
// FailOpen: token economy is availability, not security. Any engine error, or an
// unusable output (not valid JSON), leaves the body unchanged and the request
// proceeds.
type Gate struct {
	id      string
	engines []CompressionEngine
	// optIn maps an engine ID to the operator's prefix-rewrite opt-in.
	optIn map[string]bool
	// record receives count-only stats; it never sees prompt content.
	record func(Stats)
	// requireValidJSON rejects an output that no longer parses as a JSON object.
	requireValidJSON bool
}

// compile-time assertions: the gate is a Gate and declares that it needs the body.
var (
	_ contracts.Gate         = (*Gate)(nil)
	_ contracts.GateDeclarer = (*Gate)(nil)
	_ contracts.BodyConsumer = (*Gate)(nil)
)

// Config configures the token gate.
type Config struct {
	// Engines are the engines to run, in order. Empty means the gate is inert.
	Engines []CompressionEngine
	// OptIn names the engines the operator opted into prefix rewrite (ADR-0015
	// §3). It only affects an ImpactHigh engine.
	OptIn map[string]bool
	// Record receives one Stats per applied engine; nil is a no-op. It is
	// observability only and receives counts, never content.
	Record func(Stats)
}

// New builds the token gate.
func New(cfg Config) *Gate {
	return &Gate{
		id:               "token",
		engines:          cfg.Engines,
		optIn:            cfg.OptIn,
		record:           cfg.Record,
		requireValidJSON: true,
	}
}

// ID implements contracts.Gate.
func (g *Gate) ID() string { return "token" }

// Stages implements contracts.Gate: the token gate compresses the request
// BEFORE the dispatch, so it acts only in the PreRequest stage.
func (g *Gate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate. The gate needs the prompt text, which
// every text model has; it requires no special capability.
func (g *Gate) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate. Token economy is availability, so the
// gate fails OPEN (ADR-0015 §6): a failure never breaks the request.
func (g *Gate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }

// NeedsBody implements contracts.BodyConsumer: the gate needs the canonical body
// to compress it (ADR-SEC-03 §2). It is the only gate that asks for the body.
func (g *Gate) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. It READS the retrieved context and
// the cache-lookup outcome (so the DAG orders it after the memory retriever and
// the semantic cache, ADR-SEC-04 §1) and WRITES the prompt text and the frozen
// prefix range (ADR-0015 §2).
func (g *Gate) Declare() contracts.Declared {
	return contracts.Declared{
		Stages: g.Stages(),
		Reads:  []contracts.DataField{contracts.FieldContext, contracts.FieldCacheLookup},
		Writes: []contracts.DataField{contracts.FieldPromptText, contracts.FieldPrefixRange},
	}
}

// PreRequest implements contracts.Gate. It compresses the body, honoring the
// frozen prefix, and returns DecisionModify when (and only when) something
// changed.
func (g *Gate) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if len(g.engines) == 0 || len(in.Body) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	original := in.Body
	// The boundary is computed ONCE from the original body and frozen. Every
	// engine is allowed to touch only bytes at offset >= prefixEnd; an engine
	// that shortened the prefix is rejected by acceptOutput below, so the offset
	// stays valid across engines.
	prefixEnd := prefixBoundary(original)
	current := original

	for _, e := range g.engines {
		if e == nil {
			continue
		}
		opts := Options{
			PrefixEnd:          prefixEnd,
			AllowPrefixRewrite: g.optIn[e.ID()] && e.CacheImpact() == ImpactHigh,
			Model:              in.Model,
		}
		out, stats, err := e.Apply(current, opts)
		if err != nil || out == nil {
			// FailOpen: a failing engine contributes nothing; the body stays as
			// it was before this engine (never truncated, ADR-0014 §3.3).
			continue
		}
		if !g.acceptOutput(current, out, e, opts) {
			// The engine violated the freeze or broke the JSON: discard its
			// change. It fails safe rather than corrupt the prompt or the cache.
			continue
		}
		// Complete an engine's stats from the actual values, so a sparse engine
		// still yields a usable record (counts only, never content).
		if stats.ID == "" {
			stats.ID = e.ID()
		}
		if stats.BytesIn == 0 {
			stats.BytesIn = len(current)
		}
		if stats.BytesOut == 0 {
			stats.BytesOut = len(out)
		}
		if stats.TokensSaved == 0 {
			stats.TokensSaved = estimateTokens(stats.BytesIn - stats.BytesOut)
		}
		if g.record != nil {
			g.record(stats)
		}
		current = out
	}

	if string(current) == string(original) {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	return contracts.Decision{Kind: contracts.DecisionModify, Body: current}, nil
}

// acceptOutput verifies an engine's output before it is adopted:
//
//   - the frozen prefix is byte-identical, UNLESS the engine is ImpactHigh and
//     the operator opted in (ADR-0015 §2/§3); and
//   - the output still parses as a JSON object (when required), so a corrupt
//     compression never reaches the upstream.
func (g *Gate) acceptOutput(before, after []byte, e CompressionEngine, opts Options) bool {
	if !opts.AllowPrefixRewrite {
		end := opts.PrefixEnd
		if end > len(before) {
			end = len(before)
		}
		if end > len(after) {
			return false // the engine shortened the frozen prefix
		}
		if string(before[:end]) != string(after[:end]) {
			return false
		}
	}
	if g.requireValidJSON && !isJSONObject(after) {
		return false
	}
	return true
}

// OnResponseChunk implements contracts.Gate. The token gate does not act
// post-commit.
func (g *Gate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate. It could feed the cache-hit signal
// back into the net-savings metric (ADR-0015 §5); this wave records the signal
// when the pipeline provides it and is otherwise inert.
func (g *Gate) PostResponse(_ context.Context, in contracts.GateInput) error {
	if g.record == nil || in.Derived == nil || in.Derived.Fields == nil {
		return nil
	}
	if cached, ok := in.Derived.Fields["cached_tokens"]; ok {
		if n, err := strconv.Atoi(cached); err == nil {
			g.record(Stats{ID: g.id + ".cache", TokensSaved: n})
		}
	}
	return nil
}

// Close implements contracts.Gate.
func (g *Gate) Close() error { return nil }

// isJSONObject reports whether b parses as a JSON object.
func isJSONObject(b []byte) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(b, &m) == nil
}
