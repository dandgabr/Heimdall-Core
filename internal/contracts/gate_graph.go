package contracts

import "github.com/dandgabr/heimdall-core/internal/domain"

// This file holds the ADDITIVE gate-graph vocabulary of ADR-0014: the closed set
// of request data fields a gate reads or writes, the `Declared` dependency
// record, the optional `GateDeclarer` interface, and the request-scoped
// `Derived` metadata.
//
// ADDITIVE: none of this changes the frozen `Gate` contract. A gate that does
// not implement `GateDeclarer` simply has no declared edges and is ordered by
// its ID (the deterministic tie-break).

// DataField is the closed vocabulary of request data a gate reads or writes.
// Closed on purpose: a new field is a contract change, not a loose string, so
// the graph stays verifiable (ADR-0014 §1).
type DataField string

const (
	// FieldModality is the modality/requirements.
	FieldModality DataField = "modality"
	// FieldCacheLookup is the cache hit / cache key.
	FieldCacheLookup DataField = "cache_lookup"
	// FieldContext is the retrieved memory context.
	FieldContext DataField = "context"
	// FieldPromptText is the system/user prompt body.
	FieldPromptText DataField = "prompt_text"
	// FieldPrefixRange is the frozen cache-prefix range (ADR-0015).
	FieldPrefixRange DataField = "prefix_range"
	// FieldPII is the PII masking outcome.
	FieldPII DataField = "pii"
	// FieldInjectionFlag is the prompt-injection verdict.
	FieldInjectionFlag DataField = "injection_flag"
	// FieldBudget is the token budget/count.
	FieldBudget DataField = "token_budget"
	// FieldRoute is the reroute/model target.
	FieldRoute DataField = "route"
)

// Declared is what a gate declares about its data. The stage ordering is derived
// from these declarations: an edge A→B exists when A writes a field B reads, or
// when B names A in After (ADR-0014 §1).
type Declared struct {
	// Stages are the stages the gate acts in (mirrors the frozen Stages()).
	Stages GateStageSet
	// Reads are the fields the gate OBSERVES (its order depends on them).
	Reads []DataField
	// Writes are the fields the gate ALTERS (they produce edges to readers).
	Writes []DataField
	// After is an EXPLICIT dependency by gate name, for a relation not
	// expressible as a data field. It is a documented exception, not the default
	// mechanism.
	After []string
}

// GateDeclarer is implemented by a gate that participates in the dependency
// graph. It is optional: a gate without it has no edges and is ordered by ID.
type GateDeclarer interface {
	// Declare returns the gate's data read/write set and explicit dependencies.
	Declare() Declared
}

// Derived is request-scoped metadata computed ONCE per request and reused across
// chunks (ADR-0014 §6). It carries exactly what a gate already received
// (request id, provider, credential, model and the sorted header NAMES), just
// without recomputation; sensitive header VALUES stay out. A nil Derived means
// "not computed" and a gate may fall back to deriving it from its own input.
type Derived struct {
	RequestID   domain.RequestID
	Provider    domain.ProviderID
	Credential  domain.CredentialID
	Model       domain.ModelID
	HeaderNames string
	// Fields is a preallocated, request-scoped field map holding the SAME
	// identity/header-name values above, so a gate can emit its record WITHOUT
	// building a fresh map per chunk. It is MUTABLE and shared across the gates
	// of one request: a gate writes its dynamic keys into it and emits
	// synchronously before the next gate runs, so a single-consumer stream sees
	// no torn record. The pipeline owns it (Derive allocates it once); a gate
	// must not retain it past its call.
	Fields map[string]string
}
