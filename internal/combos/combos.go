// Package combos holds the named, persisted routing combos of F3 (ADR-0013).
//
// A combo is a named, reusable route: it maps a name to a policy (one of the
// strategies of ADR-0009) and an ordered list of steps. Steps may target a
// concrete model, another combo (a reference, which makes the set a DAG) or a
// provider wildcard. The package is a LEAF: it imports only internal/contracts,
// internal/domain and the standard library, so the store can persist combos and
// the Router can expand them without an import cycle.
//
// # Where the state lives
//
// This package is pure DATA + pure VALIDATION. It has no clock, no I/O and no
// mutable state. Persistence lives in internal/store (ComboStore); the rotation
// cursor (round-robin, fill-first) is execution state that is IN-MEMORY and is
// NOT persisted (ADR-0013 §5) — a restart resets the cursor.
//
// # Config vs database
//
// Combos are NOT declared in the config file. The `[[providers]]` block declares
// provider TRANSPORT (bootstrap/policy); combos are operator DATA that changes at
// runtime, exactly like credentials — which also live in the database, not in
// config. Declaring combos in config would create a second source of truth and a
// boot-time import path, so the decision is: config declares bootstrap and
// transport; the database owns credentials and combos (ADR-0001/ADR-0013 §1).
//
// # Validation is at SAVE time
//
// Every graph property (references resolve, no cycle, depth cap, fan-out cap,
// provider allowlist) is validated when a combo is saved, never on the request
// path: a request must cost only the Router.Resolve. A bad combo fails with a
// typed route.* error and never reaches routing.
package combos

import (
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// CurrentSchema is the version of the persisted combo format this build writes.
// v1 was the "simple list" of the old plan (never shipped); v2 is the step model
// with kinds, weights and references. A combo with a LOWER version is upgraded
// on load; a HIGHER version is refused fail-closed (ADR-0013 §4), the same
// posture as config_version.
const CurrentSchema = 2

// Caps on the reference graph and fusion fan-out. They are hard ceilings in the
// binary (not operator config) so a combo can never make the Router recurse or
// fan out without bound (ADR-0009 §3, ADR-0013 §3).
const (
	// MaxDepth is the maximum chain of combo-refs from a combo.
	MaxDepth = 8
	// MaxFanout is the maximum number of parallel branches a fusion combo may
	// declare. A fusion combo's step count is its fan-out.
	MaxFanout = 8
)

// StepKind is the type of a combo step. Exactly one target per step.
type StepKind string

const (
	// StepModel targets one model, provider-agnostic: the Router expands it to
	// every known provider that declares the model.
	StepModel StepKind = "model"
	// StepComboRef targets another combo by name; this is what makes the set a
	// DAG.
	StepComboRef StepKind = "combo-ref"
	// StepProviderWildcard targets every model of one provider.
	StepProviderWildcard StepKind = "provider-wildcard"
)

// allStepKinds is the closed set, used by IsKnown.
var allStepKinds = []StepKind{StepModel, StepComboRef, StepProviderWildcard}

// IsKnown reports whether the kind is one of the three defined.
func (k StepKind) IsKnown() bool {
	for _, known := range allStepKinds {
		if k == known {
			return true
		}
	}
	return false
}

// Step is one combo step. Exactly ONE of the target fields applies, selected by
// Kind: Ref holds the model id, the referenced combo id or the provider id.
type Step struct {
	Kind StepKind `json:"kind"`
	// Ref is the target: a model id (StepModel), a combo id (StepComboRef) or a
	// provider id (StepProviderWildcard). It is never empty.
	Ref string `json:"ref"`
	// Weight feeds the weighted strategy; 0 or absent means 1 (ADR-0009 §2).
	Weight int `json:"weight,omitempty"`
	// Prompt is an optional prompt injected for this step (pipeline).
	Prompt string `json:"prompt,omitempty"`
	// AllowedConnections restricts the step to the listed credentials. Empty
	// means any healthy credential of the target (ADR-0013 §2).
	AllowedConnections []domain.CredentialID `json:"allowed_connections,omitempty"`
	// FallbackOnlyOnQuota makes failover for this step happen only on quota
	// exhaustion (ScopeCredential/429), not on a client error (ADR-0013 §2).
	FallbackOnlyOnQuota bool `json:"fallback_only_on_quota,omitempty"`
}

// WeightOrOne returns the step weight, defaulting a non-positive weight to 1.
func (s Step) WeightOrOne() int {
	if s.Weight <= 0 {
		return 1
	}
	return s.Weight
}

// Combo is a named, persisted route.
//
// ID is the persisted primary key and equals the name; Name is the declared,
// operator-facing name. They are kept as separate fields because the schema
// stores the name as the key while the model carries a stable typed id, but a
// constructor always sets ID = domain.ComboID(Name) so the two never diverge.
type Combo struct {
	ID       domain.ComboID         `json:"id"`
	Name     string                 `json:"name"`
	Strategy contracts.StrategyKind `json:"strategy"`
	Steps    []Step                 `json:"steps"`
	// SchemaVer is the persisted format version (see CurrentSchema).
	SchemaVer int `json:"schema_ver"`
	// Depth is the longest chain of combo-refs from this combo; it is DERIVED
	// and recomputed on save, never trusted from the store blindly.
	Depth int `json:"depth"`
	// CreatedAt and UpdatedAt are set by the store.
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

// NewCombo builds a combo with the current schema and ID derived from the name.
// It does not validate; call Validate (and ValidateGraph) on save.
func NewCombo(name string, strategy contracts.StrategyKind, steps []Step) Combo {
	id := domain.ComboID(name)
	return Combo{
		ID:        id,
		Name:      name,
		Strategy:  strategy,
		Steps:     steps,
		SchemaVer: CurrentSchema,
	}
}

// ProviderSet is the allowlist of known providers, as the validator needs it.
// The provider registry (internal/providers) satisfies it; keeping it an
// interface is what lets this package stay a leaf.
type ProviderSet interface {
	// Has reports whether a provider family is registered.
	Has(domain.ProviderID) bool
	// DeclaresModel reports whether any registered provider declares the model.
	DeclaresModel(domain.ModelID) bool
}
