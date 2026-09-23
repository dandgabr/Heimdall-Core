// Package pipeline holds the GateChain: the ordered execution of gates with the
// pre-commit / post-commit distinction that the frozen contracts.Gate defines.
//
// The chain is deliberately small and owns no I/O. Its job is to run the
// registered gates for one stage, apply their failure policy, and stop the
// pipeline when a gate blocks. Committed is threaded through so a post-commit
// gate can only emit a ChunkDecision (no reroute, no model swap).
//
// ORDER (ADR-0014 §1): the chain receives the per-stage order already computed
// by the gate registry (internal/gates), so it never orders on the request path
// and never iterates a map. The legacy New([]Gate) derives the stage slices by
// partitioning its input, preserving the caller's order.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Chain runs gates in a deterministic order, per stage.
type Chain struct {
	pre   []contracts.Gate
	chunk []contracts.Gate
	post  []contracts.Gate
	all   []contracts.Gate
}

// New builds a chain from a flat gate list by partitioning the gates by the
// stages they declare, preserving the input order within each stage. It is the
// compatibility constructor; the composition root uses NewOrdered with the order
// computed by the gate registry.
func New(gates []contracts.Gate) (*Chain, error) {
	for i, g := range gates {
		if g == nil {
			return nil, domain.New(domain.CodeInternal,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": fmt.Sprintf("gate %d is nil", i)}),
			)
		}
	}
	pre, chunk, post := partition(gates)
	return &Chain{pre: pre, chunk: chunk, post: post, all: append([]contracts.Gate(nil), gates...)}, nil
}

// NewOrdered builds a chain from the per-stage order the registry computed. A
// nil gate in any slice is rejected: a half-built chain would silently drop a
// security control.
//
// All holds each DISTINCT gate once, sorted by ID, so a gate present in several
// stages is closed/logged once and Gates() never repeats it.
func NewOrdered(pre, chunk, post []contracts.Gate) (*Chain, error) {
	seen := map[string]contracts.Gate{}
	for _, stage := range [][]contracts.Gate{pre, chunk, post} {
		for i, g := range stage {
			if g == nil {
				return nil, domain.New(domain.CodeInternal,
					domain.WithHTTPStatus(500),
					domain.WithParams(map[string]string{"reason": fmt.Sprintf("ordered gate %d is nil", i)}),
				)
			}
			seen[g.ID()] = g
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	all := make([]contracts.Gate, 0, len(ids))
	for _, id := range ids {
		all = append(all, seen[id])
	}
	return &Chain{
		pre:   append([]contracts.Gate(nil), pre...),
		chunk: append([]contracts.Gate(nil), chunk...),
		post:  append([]contracts.Gate(nil), post...),
		all:   all,
	}, nil
}

// partition splits a flat gate list into the three stage slices, preserving the
// input order within each stage.
func partition(gates []contracts.Gate) (pre, chunk, post []contracts.Gate) {
	for _, g := range gates {
		if g.Stages().Has(contracts.StagePreRequest) {
			pre = append(pre, g)
		}
		if g.Stages().Has(contracts.StageOnResponseChunk) {
			chunk = append(chunk, g)
		}
		if g.Stages().Has(contracts.StagePostResponse) {
			post = append(post, g)
		}
	}
	return pre, chunk, post
}

// Gates returns every gate in stage order (pre, chunk, post). It returns a COPY:
// a caller that mutated the slice would otherwise be able to null out a gate and
// silently disable a security control.
func (c *Chain) Gates() []contracts.Gate {
	out := make([]contracts.Gate, len(c.all))
	copy(out, c.all)
	return out
}

// ConsumesRequestBody reports whether ANY pre-request gate needs the request
// body (contracts.BodyConsumer). The HTTP boundary calls it once per request to
// decide whether to populate GateInput.Body; when false, the body stays nil so a
// gate that did not ask can never read a payload (ADR-SEC-03 §2).
func (c *Chain) ConsumesRequestBody() bool {
	return contracts.AnyConsumesBody(c.pre)
}

// Derive computes the request-scoped metadata ONCE per request (ADR-0014 §6):
// the identity fields are copied, the header NAMES are sorted and joined, and a
// preallocated Fields map is filled with them. No header VALUE is read,
// preserving SEC-13. The result is threaded by the caller into GateInput and
// ChunkInput so a gate never rebuilds it per chunk.
func Derive(in contracts.GateInput) *contracts.Derived {
	names := headerNames(in.Headers)
	d := &contracts.Derived{
		RequestID:   in.RequestID,
		Provider:    in.Provider,
		Credential:  in.Credential,
		Model:       in.Model,
		HeaderNames: names,
		Fields:      make(map[string]string, 6),
	}
	d.Fields["request_id"] = in.RequestID.String()
	d.Fields["provider"] = string(in.Provider)
	d.Fields["credential"] = string(in.Credential)
	d.Fields["model"] = string(in.Model)
	if names != "" {
		d.Fields["header_names"] = names
	}
	return d
}

// headerNames returns the sorted, comma-joined header NAMES of a header map. It
// never reads a value.
func headerNames(h map[string][]string) string {
	if len(h) == 0 {
		return ""
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// PreRequest runs every pre-request gate in graph order.
//
// The request-scoped Derived is computed here, once, if the caller did not
// already supply it, and is returned on the Decision so the caller can reuse the
// SAME reference for the chunk stage (ADR-0014 §6). It stops at the first Block
// or Reroute (both terminal) and returns the accumulated decision. A Modify
// updates the working input for the REMAINING gates. On a gate error the
// contract's FailurePolicy decides: FailClosed aborts with the gate's error;
// FailOpen logs and continues with the input UNMODIFIED by the failing gate
// (ADR-0014 §3.3).
func (c *Chain) PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error) {
	in.Committed = false
	if in.Derived == nil {
		in.Derived = Derive(in)
	}

	// Tracks whether ANY gate modified the request, so the accumulated Modify is
	// returned to the CALLER and not only applied to the downstream working
	// input. Without this a Modify gate would be a no-op for the request that
	// actually goes upstream (the F4-wave-1 chain lost it).
	modified := false

	for _, g := range c.pre {
		decision, err := g.PreRequest(ctx, in)
		if err != nil {
			if g.FailurePolicy() == contracts.FailClosed {
				return contracts.Decision{}, err
			}
			// FailOpen: continue with the input as it was BEFORE this gate, so a
			// half-applied Modify is never published (ADR-0014 §3.3).
			continue
		}

		switch decision.Kind {
		case contracts.DecisionContinue:
			continue
		case contracts.DecisionModify:
			// A Modify rewrites the request for the REMAINING gates AND is
			// surfaced to the caller.
			if decision.Body != nil {
				in.Body = decision.Body
				modified = true
			}
			if decision.Headers != nil {
				in.Headers = decision.Headers
				modified = true
			}
			continue
		case contracts.DecisionBlock:
			if decision.Synthetic == nil {
				return contracts.Decision{}, contractError(g.ID(), "blocked without a synthetic response")
			}
			decision.Derived = in.Derived
			return decision, nil
		case contracts.DecisionReroute:
			if decision.Reroute == nil {
				return contracts.Decision{}, contractError(g.ID(), "rerouted without a target")
			}
			decision.Derived = in.Derived
			return decision, nil
		default:
			return contracts.Decision{}, contractError(g.ID(), "returned an unknown decision")
		}
	}
	if modified {
		return contracts.Decision{Kind: contracts.DecisionModify, Body: in.Body, Headers: in.Headers, Derived: in.Derived}, nil
	}
	return contracts.Decision{Kind: contracts.DecisionContinue, Derived: in.Derived}, nil
}

// OnResponseChunk runs every chunk gate in graph order.
//
// Committed is forced true: the first byte has already been sent, so the only
// legal outcomes are PassThrough, Replace and Drop. A post-commit Reroute is a
// contract violation (error.internal, ADR-0014 §2). On a FailClosed error the
// caller turns the failure into a terminal SSE event; a FailOpen error is
// swallowed and the chunk passes through unchanged.
func (c *Chain) OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	in.Committed = true
	stampChunkScalars(in.Derived, in.Index, len(in.Body))

	for _, g := range c.chunk {
		decision, err := g.OnResponseChunk(ctx, in)
		if err != nil {
			if g.FailurePolicy() == contracts.FailClosed {
				return contracts.ChunkDecision{}, err
			}
			continue
		}
		switch decision.Kind {
		case contracts.ChunkPassThrough:
			continue
		case contracts.ChunkReplace:
			return decision, nil
		case contracts.ChunkDrop:
			return decision, nil
		default:
			return contracts.ChunkDecision{}, contractError(g.ID(), "returned an unknown chunk decision")
		}
	}
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse runs every post-response gate in graph order. It is ALWAYS
// FailOpen (ADR-0014 §2): it runs off the first-byte path, so no gate failure
// aborts it. Every gate runs; the first error is returned so it stays observable
// (the caller logs it, never acts on it).
func (c *Chain) PostResponse(ctx context.Context, in contracts.GateInput) error {
	if in.Derived == nil {
		in.Derived = Derive(in)
	}
	// Drop any per-chunk scalars the chunk stage stamped, so a post-response
	// record does not carry a stale chunk index/size.
	clearChunkScalars(in.Derived)
	var firstErr error
	for _, g := range c.post {
		if err := g.PostResponse(ctx, in); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close releases every gate. It attempts all of them and returns the joined
// errors, so one misbehaving Close does not strand the others.
func (c *Chain) Close() error {
	var errs []error
	for _, g := range c.all {
		if err := g.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// stampChunkScalars writes the per-chunk scalars (index, size) into the shared
// request-scoped Fields map ONCE per chunk, so every gate emits them without
// re-formatting. It is the chunk-path half of ADR-0014 §6: the per-request
// metadata is computed once in Derive, and the per-chunk scalars once here, so
// neither the metadata nor the formatting grows with the number of gates. The
// keys are removed after the chunk stage by clearChunkScalars so they never
// leak into a post-response record.
func stampChunkScalars(d *contracts.Derived, index, size int) {
	if d == nil || d.Fields == nil {
		return
	}
	d.Fields["chunk_index"] = strconv.Itoa(index)
	d.Fields["chunk_bytes"] = strconv.Itoa(size)
}

// clearChunkScalars removes the per-chunk keys the chunk stage stamped, so a
// later PostResponse record does not carry a stale chunk index/size.
func clearChunkScalars(d *contracts.Derived) {
	if d == nil || d.Fields == nil {
		return
	}
	delete(d.Fields, "chunk_index")
	delete(d.Fields, "chunk_bytes")
}

// contractError is a gate contract violation (ADR-0014 §2): error.internal,
// because the gate broke its contract, not the client's request.
func contractError(id, reason string) error {
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(500),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": "gate " + id + " " + reason}),
	)
}
