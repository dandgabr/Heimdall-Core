package providers

import (
	"fmt"
	"sort"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/executors"
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

	baseURL  string
	allowLo  bool
	authHead executors.AuthHeaderStyle
	ttft     time.Duration
	idle     time.Duration
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
	// BaseURL is the upstream root the executor dials, e.g.
	// https://api.example.com/v1. Empty means BuildExecutor refuses: an executor
	// without a destination cannot run.
	BaseURL string
	// AllowLoopback unlocks the loopback exception for a local runtime. It is
	// honoured only for an explicit loopback IP literal by the egress policy.
	AllowLoopback bool
	// AuthHeader selects the auth header shape; defaults to Bearer.
	AuthHeader executors.AuthHeaderStyle
	// ResponseHeaderTimeout bounds TTFT; zero uses the executor default.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds the gap between stream chunks.
	IdleTimeout time.Duration
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
		baseURL:  opts.BaseURL,
		allowLo:  opts.AllowLoopback,
		authHead: opts.AuthHeader,
		ttft:     opts.ResponseHeaderTimeout,
		idle:     opts.IdleTimeout,
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

// BuildExecutor implements contracts.ProviderFamily. It builds the real F2.2
// transport+auth executor for this family. It refuses a credential from another
// family, and refuses when no BaseURL was configured (an executor without a
// destination cannot run) or when the auth mode is unsupported.
func (f *OpenAICompat) BuildExecutor(cred contracts.Credential, deps contracts.ExecutorDeps) (contracts.Executor, error) {
	if cred.Provider != f.id {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"reason": fmt.Sprintf("credential provider %s does not match family %s", cred.Provider, f.id),
			}),
		)
	}
	if f.baseURL == "" {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "family " + string(f.id) + " has no base url"}),
		)
	}
	if !f.supportsAuthMode(cred.AuthMode) {
		// The credential's mode is not one this provider supports: name both the
		// provider and the offending mode (provider.auth_mode_unsupported), not
		// the stored-credential code whose message expects {id}.
		return nil, domain.New(domain.CodeProviderAuthModeUnsupported,
			domain.WithHTTPStatus(500),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"provider": string(f.id), "mode": cred.AuthMode.String()}),
		)
	}

	return executors.New(executors.Config{
		Family:                f.id,
		BaseURL:               f.baseURL,
		AllowLoopback:         f.allowLo,
		AuthStyle:             f.authHead,
		ResponseHeaderTimeout: f.ttft,
		IdleTimeout:           f.idle,
	}, deps)
}

// supportsAuthMode reports whether the family declares the credential's mode.
func (f *OpenAICompat) supportsAuthMode(mode contracts.AuthMode) bool {
	for _, m := range f.authMode {
		if m == mode {
			return true
		}
	}
	return false
}
