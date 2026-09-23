// Package gates holds the gate ENGINE (ADR-0014: registry, dependency graph,
// per-stage topological order, failure-policy validation) and the built-in gate
// implementations.
//
// F4-wave-1 ships the engine plus the trivial logger gate; the token, memory and
// security gates land in later waves and register through the same registry. A
// gate receives the MINIMUM content it needs (ADR-SEC-03 / SEC-13): the logger
// gate asks for no body at all.
package gates

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Logger is the trivial observability gate.
//
// It participates in all three stages but touches only METADATA: provider,
// credential id, model, request id and header NAMES. It never reads or logs a
// body and never reads an auth header VALUE, so a credential cannot pass through
// it. Its failure policy is FailOpen: observability must never take down the
// pipeline.
type Logger struct {
	// Sink receives one structured record per stage. It is a plain function so
	// the gate carries no logger dependency and is trivially testable.
	Sink func(stage string, fields map[string]string)
}

// NewLogger builds the gate with a sink. A nil sink is replaced by a no-op so a
// caller cannot panic the pipeline by forgetting to wire one.
func NewLogger(sink func(stage string, fields map[string]string)) *Logger {
	if sink == nil {
		sink = func(string, map[string]string) {}
	}
	return &Logger{Sink: sink}
}

// ID implements contracts.Gate.
func (g *Logger) ID() string { return "logger" }

// Stages declares participation in every stage.
func (g *Logger) Stages() contracts.GateStageSet {
	return contracts.StageSet(
		contracts.StagePreRequest,
		contracts.StageOnResponseChunk,
		contracts.StagePostResponse,
	)
}

// RequiredCaps implements contracts.Gate: the logger needs nothing specific.
func (g *Logger) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate.
func (g *Logger) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }

// Declare implements contracts.GateDeclarer. The logger is pure observation: it
// reads no field and writes none, so it has no data edge and is ordered by ID
// (its position among the unordered gates is the deterministic tie-break).
func (g *Logger) Declare() contracts.Declared {
	return contracts.Declared{
		Stages: g.Stages(),
	}
}

// PreRequest implements contracts.Gate. It logs metadata only and always
// continues.
func (g *Logger) PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error) {
	g.emit("pre_request", metadataOf(in.Derived, in.RequestID, in.Provider, in.Credential, in.Model, in.Headers))
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}

// OnResponseChunk implements contracts.Gate. It logs the chunk INDEX and size,
// never the bytes. The shared metadata is REUSED from the pre-request stage
// (ADR-0014 §6): when the pipeline supplied Derived, its request-scoped Fields
// map is written into directly (no per-gate map, no header join), so the chunk
// cost does not grow with the number of gates.
func (g *Logger) OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	fields := metadataOf(in.Derived, in.RequestID, in.Provider, in.Credential, in.Model, in.Headers)
	// When the pipeline supplied Derived, the per-chunk scalars were already
	// stamped into the shared map once (ADR-0014 §6), so the gate adds nothing.
	// Without Derived the gate derives them itself, preserving standalone use.
	if in.Derived == nil || in.Derived.Fields == nil {
		fields["chunk_index"] = itoa(in.Index)
		fields["chunk_bytes"] = itoa(len(in.Body))
	}
	g.emit("response_chunk", fields)
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate.
func (g *Logger) PostResponse(ctx context.Context, in contracts.GateInput) error {
	g.emit("post_response", metadataOf(in.Derived, in.RequestID, in.Provider, in.Credential, in.Model, in.Headers))
	return nil
}

// Close implements contracts.Gate.
func (g *Logger) Close() error { return nil }

func (g *Logger) emit(stage string, fields map[string]string) {
	if g.Sink != nil {
		g.Sink(stage, fields)
	}
}

// metadataOf returns the non-secret field map shared by the stages. When the
// pipeline supplied the request-scoped Derived (ADR-0014 §6), its preallocated
// Fields map is returned DIRECTLY: the identity fields and the joined header
// names were computed once per request, so neither this gate nor a per-chunk
// call rebuilds them. The caller (emit) must consume the map synchronously and
// not retain it. Otherwise the gate falls back to deriving a fresh map from its
// own input, preserving standalone behaviour.
//
// Header VALUES are never included; only sorted header names, which is enough to
// diagnose a routing problem without touching credentials.
func metadataOf(d *contracts.Derived, requestID domain.RequestID, provider domain.ProviderID, credential domain.CredentialID, model domain.ModelID, headers http.Header) map[string]string {
	if d != nil && d.Fields != nil {
		return d.Fields
	}
	fields := map[string]string{
		"request_id": string(requestID),
		"provider":   string(provider),
		"credential": string(credential),
		"model":      string(model),
	}
	if d != nil {
		fields["request_id"] = d.RequestID.String()
		fields["provider"] = string(d.Provider)
		fields["credential"] = string(d.Credential)
		fields["model"] = string(d.Model)
		if d.HeaderNames != "" {
			fields["header_names"] = d.HeaderNames
		}
		return fields
	}
	if len(headers) > 0 {
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		sort.Strings(names)
		fields["header_names"] = strings.Join(names, ",")
	}
	return fields
}

func itoa(n int) string { return strconv.Itoa(n) }
