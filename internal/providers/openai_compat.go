package providers

import (
	"fmt"
	"sort"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// OpenAICompat is the declarative OpenAI-compatible family.
//
// F1.4 ships only the skeleton: the protocol is fixed to openai, the auth mode
// to APIKey, and the capability table is a static, configurable map. Concrete
// per-provider families (Antigravity, z.ai, Ollama Cloud, Command Code) are
// registered as descriptors in F1.5 and reuse this type.
//
// The family is DATA, not code: two providers that speak the same dialect
// differ only in the descriptor and the model table they are constructed with.
type OpenAICompat struct {
	id       domain.ProviderID
	desc     contracts.ProviderDescriptor
	models   map[domain.ModelID]modelSpec
	authMode []contracts.AuthMode
}

// modelSpec is the declared capability/modality of one model.
type modelSpec struct {
	caps contracts.Capabilities
	mods contracts.ModalitySet
}

// OpenAICompatOptions configures a declarative family.
type OpenAICompatOptions struct {
	// ID is the family identifier.
	ID domain.ProviderID
	// Descriptor is the static provider description (endpoints, scopes).
	Descriptor contracts.ProviderDescriptor
	// AuthModes defaults to [AuthAPIKey] when empty.
	AuthModes []contracts.AuthMode
	// Models maps a model name to its declared capabilities. Unknown models are
	// reported as ok=false by Capabilities, which is what makes the Router skip
	// a family it cannot reason about.
	Models map[domain.ModelID]ModelCapabilities
}

// ModelCapabilities is the declarative capability/modality pair for a model.
type ModelCapabilities struct {
	Capabilities contracts.Capabilities
	Modalities   contracts.ModalitySet
}

// NewOpenAICompat builds the family. It rejects an empty ID because a family
// without an identity cannot be registered or routed to.
func NewOpenAICompat(opts OpenAICompatOptions) (*OpenAICompat, error) {
	if opts.ID == "" {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "empty provider id"}),
		)
	}

	desc := opts.Descriptor
	if desc.ID == "" {
		desc.ID = opts.ID
	}
	if desc.Protocol == "" {
		desc.Protocol = contracts.WireOpenAI
	}

	authModes := opts.AuthModes
	if len(authModes) == 0 {
		authModes = []contracts.AuthMode{contracts.AuthAPIKey}
	}

	models := make(map[domain.ModelID]modelSpec, len(opts.Models))
	for name, mc := range opts.Models {
		models[name] = modelSpec{caps: mc.Capabilities, mods: mc.Modalities}
	}

	return &OpenAICompat{
		id:       opts.ID,
		desc:     desc,
		models:   models,
		authMode: authModes,
	}, nil
}

// ID implements contracts.ProviderFamily.
func (f *OpenAICompat) ID() domain.ProviderID { return f.id }

// AuthModes implements contracts.ProviderFamily.
func (f *OpenAICompat) AuthModes() []contracts.AuthMode {
	out := make([]contracts.AuthMode, len(f.authMode))
	copy(out, f.authMode)
	return out
}

// Protocol implements contracts.ProviderFamily.
func (f *OpenAICompat) Protocol() contracts.WireFormat { return f.desc.Protocol }

// Descriptor returns the static provider description.
func (f *OpenAICompat) Descriptor() contracts.ProviderDescriptor { return f.desc }

// Capabilities implements contracts.ProviderFamily. An unknown model returns
// ok=false; the family never invents an empty capability set, which the
// contract explicitly forbids.
func (f *OpenAICompat) Capabilities(model domain.ModelID) (contracts.Capabilities, bool) {
	spec, ok := f.models[model]
	if !ok {
		return 0, false
	}
	return spec.caps, true
}

// Modalities reports the declared modalities for a model. It is an extra
// accessor beyond the frozen contract, used by the catalog builder.
func (f *OpenAICompat) Modalities(model domain.ModelID) (contracts.ModalitySet, bool) {
	spec, ok := f.models[model]
	if !ok {
		return 0, false
	}
	return spec.mods, true
}

// Models returns the declared model IDs in deterministic order.
func (f *OpenAICompat) Models() []domain.ModelID {
	names := make([]string, 0, len(f.models))
	for name := range f.models {
		names = append(names, string(name))
	}
	sort.Strings(names)
	out := make([]domain.ModelID, 0, len(names))
	for _, n := range names {
		out = append(out, domain.ModelID(n))
	}
	return out
}

// BuildExecutor implements contracts.ProviderFamily.
//
// TODO(F2): the real Executor is the transport+auth contract that lands in F2.
// F1.4 returns a documented stub so the registry can be exercised end to end
// without inventing a contract that F2 will replace. The stub satisfies the
// frozen seam (contracts.Executor) only.
func (f *OpenAICompat) BuildExecutor(cred contracts.Credential, deps contracts.ExecutorDeps) (contracts.Executor, error) {
	if cred.Provider != f.id {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"reason": fmt.Sprintf("credential provider %s does not match family %s", cred.Provider, f.id),
			}),
		)
	}
	return stubExecutor{family: f.id}, nil
}

// stubExecutor is the F1 placeholder for the F2 Executor. It carries only the
// family identity, which is all the frozen seam requires.
type stubExecutor struct {
	family domain.ProviderID
}

// Family implements contracts.Executor.
func (e stubExecutor) Family() domain.ProviderID { return e.family }
