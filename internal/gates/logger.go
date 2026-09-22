// Package gates holds the built-in gate implementations.
//
// F1 ships only the trivial logger gate (the plan's "gate trivial de logger");
// the token, memory and security engines are F4. A gate receives the MINIMUM
// content it needs (ADR-003 / SEC-13): the logger gate asks for no body at all.
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

// PreRequest implements contracts.Gate. It logs metadata only and always
// continues.
func (g *Logger) PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error) {
	g.emit("pre_request", metadata(in.RequestID.String(), in.Provider, in.Credential, in.Model, in.Headers))
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}

// OnResponseChunk implements contracts.Gate. It logs the chunk INDEX and size,
// never the bytes.
func (g *Logger) OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	fields := metadata(in.RequestID.String(), in.Provider, in.Credential, in.Model, in.Headers)
	fields["chunk_index"] = itoa(in.Index)
	fields["chunk_bytes"] = itoa(len(in.Body))
	g.emit("response_chunk", fields)
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate.
func (g *Logger) PostResponse(ctx context.Context, in contracts.GateInput) error {
	g.emit("post_response", metadata(in.RequestID.String(), in.Provider, in.Credential, in.Model, in.Headers))
	return nil
}

// Close implements contracts.Gate.
func (g *Logger) Close() error { return nil }

func (g *Logger) emit(stage string, fields map[string]string) {
	if g.Sink != nil {
		g.Sink(stage, fields)
	}
}

// metadata builds the non-secret field map shared by the stages. Header VALUES
// are never included; only sorted header names, which is enough to diagnose a
// routing problem without touching credentials.
func metadata(requestID string, provider domain.ProviderID, credential domain.CredentialID, model domain.ModelID, headers http.Header) map[string]string {
	fields := map[string]string{
		"request_id": requestID,
		"provider":   string(provider),
		"credential": string(credential),
		"model":      string(model),
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
