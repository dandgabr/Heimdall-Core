package security

import (
	"context"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// CredentialMasker is the containment gate of phase 1 (ADR-SEC-04 §1): it
// removes upstream credentials the client pasted INTO the request body before
// the body reaches the semantic cache, the memory store or any upstream.
// Masking runs through the CENTRAL redactor (i18n.RedactString), so the rules
// that protect every log line protect the prompt too — one source of truth,
// per ADR-003. The gate never logs: its only output is the rewritten body and
// a Meta count of rewritten string values.
//
// FailurePolicy is FailClosed: a body this gate cannot process aborts the
// request, because forwarding unaudited content is the failure the gate exists
// to prevent.
type CredentialMasker struct{}

// Compile-time assertions: the gate is a Gate, declares its graph edges and
// needs the body.
var (
	_ contracts.Gate         = (*CredentialMasker)(nil)
	_ contracts.GateDeclarer = (*CredentialMasker)(nil)
	_ contracts.BodyConsumer = (*CredentialMasker)(nil)
)

// NewCredentialMasker builds the gate.
func NewCredentialMasker() *CredentialMasker { return &CredentialMasker{} }

// ID implements contracts.Gate.
func (g *CredentialMasker) ID() string { return IDCredentialMasker }

// Stages implements contracts.Gate: containment runs pre-request only.
func (g *CredentialMasker) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate: masking needs no protocol feature.
func (g *CredentialMasker) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate.
func (g *CredentialMasker) FailurePolicy() contracts.FailurePolicy { return contracts.FailClosed }

// NeedsBody implements contracts.BodyConsumer.
func (g *CredentialMasker) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. It WRITES prompt_text (the
// rewritten body), so every gate that reads the prompt is ordered after it; it
// reads nothing, so nothing delays it inside its phase.
func (g *CredentialMasker) Declare() contracts.Declared {
	return contracts.Declared{
		Stages: g.Stages(),
		Writes: []contracts.DataField{contracts.FieldPromptText},
	}
}

// PreRequest implements contracts.Gate. A body with no secret match is
// returned byte-identical and the gate continues without a Modify, so a clean
// request pays one scan and nothing else.
func (g *CredentialMasker) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if len(in.Body) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	out, hits, err := mapJSONStrings(in.Body, i18n.RedactString)
	if err != nil {
		return contracts.Decision{}, err
	}
	if hits == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	setMeta(in.Meta, IDCredentialMasker+".redactions", itoa(hits))
	return contracts.Decision{Kind: contracts.DecisionModify, Body: out}, nil
}

// OnResponseChunk implements contracts.Gate: no post-commit action.
func (g *CredentialMasker) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate: nothing to observe.
func (g *CredentialMasker) PostResponse(context.Context, contracts.GateInput) error { return nil }

// Close implements contracts.Gate.
func (g *CredentialMasker) Close() error { return nil }
