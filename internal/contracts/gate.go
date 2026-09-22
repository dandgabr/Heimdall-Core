package contracts

import (
	"context"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the Gate contract of F1 (plan v2, F1; review note
// "Mudanças estruturais (gates)" and ADR-003). Concrete gates (token, memory,
// security) are F4 and are NOT implemented here; F1 ships only a trivial logger
// gate against this interface.
//
// The contract is implementation-agnostic on purpose: it must NOT leak native
// types that would prevent a future WASM adapter (post-v1) from implementing a
// third-party gate. Every field crossing the boundary is a plain value
// (bytes, strings, maps), never an interface or a function.

// GateStage is one phase of the pipeline a gate can participate in.
type GateStage uint8

const (
	// StagePreRequest runs before routing and execution.
	StagePreRequest GateStage = iota
	// StageOnResponseChunk runs per streamed chunk, after the first byte.
	StageOnResponseChunk
	// StagePostResponse runs once after the exchange, for accounting/learning.
	StagePostResponse
)

// GateStageSet is a bitmask of stages. A gate declares every stage it needs;
// registering a gate for no stage is a programming error the registry rejects.
type GateStageSet uint8

// StageSet builds a set from stages.
func StageSet(stages ...GateStage) GateStageSet {
	var s GateStageSet
	for _, st := range stages {
		s |= 1 << st
	}
	return s
}

// Has reports whether the set contains the stage.
func (s GateStageSet) Has(st GateStage) bool { return s&(1<<st) != 0 }

// Empty reports whether no stage is declared.
func (s GateStageSet) Empty() bool { return s == 0 }

// GateCaps is the capability axis a gate requires. It is an ALIAS of
// Capabilities (identity.go) rather than a second type, because it is the same
// concept: the pipeline runs a gate only when the resolved route satisfies
// everything RequiredCaps() asks for. An alias keeps the two comparable without
// a conversion.
type GateCaps = Capabilities

// FailurePolicy is declared PER GATE, never globally. Security gates fail
// closed (a failure blocks); availability-oriented gates fail open (a failure
// is logged and the pipeline continues). There is no silent default: every gate
// states its policy.
type FailurePolicy uint8

const (
	// FailClosed: a gate error aborts the request.
	FailClosed FailurePolicy = iota
	// FailOpen: a gate error is logged and ignored.
	FailOpen
)

func (p FailurePolicy) String() string {
	if p == FailOpen {
		return "fail_open"
	}
	return "fail_closed"
}

// DecisionKind is the PRE-COMMIT vocabulary. After the first downstream byte
// (see Committed), the vocabulary narrows to ChunkDecision: no reroute and no
// model swap are legal anymore.
type DecisionKind uint8

const (
	// DecisionContinue: the gate has no objection.
	DecisionContinue DecisionKind = iota
	// DecisionModify: replace the request (body/headers) and continue. Legal
	// only before commit.
	DecisionModify
	// DecisionBlock: terminate with Synthetic. This is a SUCCESS path when the
	// synthetic is a semantic-cache hit; the pipeline emits Synthetic as the
	// response rather than an error.
	DecisionBlock
	// DecisionReroute: send the request to a different provider/model. Legal
	// only before commit, and only to a target on the reroute allowlist
	// (ADR-003 / SEC-10).
	DecisionReroute
)

// RerouteTarget names a pre-commit reroute destination. The pipeline validates
// Provider against the configured allowlist before acting; a target not on the
// list turns the decision into a fail-closed error rather than an open redirect.
type RerouteTarget struct {
	Provider domain.ProviderID
	Model    domain.ModelID
}

// SyntheticResponse is a response a gate produces without calling upstream
// (semantic cache hit, canned denial). Status defaults to 200 when zero.
type SyntheticResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
	// CacheHit distinguishes a semantic-cache hit (success) from a policy
	// denial (also delivered as a response, not an HTTP error). Both are
	// DecisionBlock; whether the outcome is "success" is a function of Status.
	CacheHit bool
}

// Decision is the pre-commit outcome of a gate's PreRequest.
type Decision struct {
	Kind      DecisionKind
	Body      []byte
	Headers   http.Header
	Synthetic *SyntheticResponse
	// Reroute is required when Kind == DecisionReroute, rejected otherwise.
	Reroute *RerouteTarget
	// Code/Params carry an i18n reason for Modify/Block; optional.
	Code   string
	Params map[string]string
}

// ChunkDecisionKind is the POST-COMMIT vocabulary. There is deliberately no
// reroute kind: once Committed is true the only terminal moves are Drop (stop
// emitting) or a gate-driven error, and the Dispatcher must not fail over.
type ChunkDecisionKind uint8

const (
	// ChunkPassThrough: forward the chunk unchanged.
	ChunkPassThrough ChunkDecisionKind = iota
	// ChunkReplace: forward Body/Headers instead of the original chunk.
	ChunkReplace
	// ChunkDrop: do not forward this chunk. The stream continues.
	ChunkDrop
)

// ChunkDecision is the post-commit outcome of a gate's OnResponseChunk.
type ChunkDecision struct {
	Kind    ChunkDecisionKind
	Body    []byte
	Headers http.Header
}

// GateInput is the request view handed to PreRequest and PostResponse. Content
// is the MINIMUM a gate needs (ADR-003 / SEC-13): a gate that does not require
// the body must not receive it. Committed is always false here; it is carried
// so a single struct serves the whole exchange and a gate cannot mistake the
// phase.
type GateInput struct {
	RequestID  domain.RequestID
	Provider   domain.ProviderID
	Credential domain.CredentialID
	Model      domain.ModelID
	// Headers are the request headers. Auth headers are already stripped by the
	// executor boundary, so a gate never sees an upstream token.
	Headers http.Header
	// Body is the request payload, or nil when the gate did not ask for it.
	Body []byte
	// Committed is always false for a PreRequest input.
	Committed bool
	// Meta is per-request scratch space. A gate MUST namespace its keys
	// ("<gateID>.<key>") to avoid colliding with another gate.
	Meta map[string]string
}

// ChunkInput is the per-chunk view handed to OnResponseChunk. Committed is true
// by construction here.
type ChunkInput struct {
	RequestID  domain.RequestID
	Provider   domain.ProviderID
	Credential domain.CredentialID
	Model      domain.ModelID
	Headers    http.Header
	// Body is this chunk's payload. It is the only content a per-chunk gate
	// should need; it must not buffer across calls.
	Body []byte
	// Index is the zero-based position of this chunk in the stream.
	Index int
	// Committed is always true for a chunk input.
	Committed bool
	Meta      map[string]string
}

// Gate is the frozen extension point (plan v2, F1). A gate is stateless across
// requests; any per-request state lives in GateInput.Meta or ChunkInput.Meta.
//
// INVARIANTS (from the review note and ADR-003):
//
//   - Reroute and Modify are PRE-COMMIT only. Once the first downstream byte is
//     sent (Committed), a gate may only emit a ChunkDecision; a Decision that
//     swaps the model or provider after commit is a contract violation.
//   - Block carries a SyntheticResponse. A semantic-cache hit is a SUCCESS
//     delivered as the response, not an error; a denial is still delivered as a
//     response (Status carries the intent).
//   - A gate receives the minimum content it needs and MUST NOT log or persist
//     payload by contract. The central Redactor is defence in depth, not the
//     policy.
//   - A gate that fails behaves per FailurePolicy(): FailClosed aborts,
//     FailOpen logs and continues. The pipeline never decides this silently.
//   - The interface leaks no native/Go-specific type across the boundary that
//     would block a WASM adapter: inputs and outputs are plain values.
type Gate interface {
	// ID is the stable gate identifier, unique within a registry.
	ID() string
	// Stages declares every stage the gate participates in.
	Stages() GateStageSet
	// RequiredCaps declares the capabilities the resolved route must satisfy
	// for this gate to run. A gate that needs nothing returns 0.
	RequiredCaps() GateCaps
	// FailurePolicy declares how a gate error is handled.
	FailurePolicy() FailurePolicy
	// PreRequest runs before routing/execution.
	PreRequest(ctx context.Context, in GateInput) (Decision, error)
	// OnResponseChunk runs per chunk after commit.
	OnResponseChunk(ctx context.Context, in ChunkInput) (ChunkDecision, error)
	// PostResponse runs once after the exchange, including on error. It must
	// not block the first byte path (async sinks are the writer's concern).
	PostResponse(ctx context.Context, in GateInput) error
	// Close releases resources. It is idempotent and called once at shutdown.
	Close() error
}
