package providers

import (
	"sort"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/executors/cloudcode"
)

// CloudCode is the declarative Google CloudCode family (ADR-0003): it speaks the
// CloudCode wire dialect and builds the internal/executors/cloudcode executor.
// Like OpenAICompat it is DATA: the descriptor carries the obfuscation layer and
// the model table is declarative.
//
// The protocol branch (ADR-0010 wiring): the composition root picks this family
// when a descriptor's Protocol is WireCloudCode, and OpenAICompat otherwise, so
// BuildExecutor is correct by construction and the two dialects never share a
// transport by accident.
type CloudCode struct {
	id       domain.ProviderID
	desc     contracts.ProviderDescriptor
	models   map[domain.ModelID]modelSpec
	authMode []contracts.AuthMode

	baseURL string
	allowLo bool
	ttft    time.Duration
	idle    time.Duration
}

// CloudCodeOptions configures the CloudCode family.
type CloudCodeOptions struct {
	ID            domain.ProviderID
	Descriptor    contracts.ProviderDescriptor
	AuthModes     []contracts.AuthMode
	Models        map[domain.ModelID]ModelCapabilities
	BaseURL       string
	AllowLoopback bool
	// ResponseHeaderTimeout and IdleTimeout mirror the OpenAICompat options.
	ResponseHeaderTimeout time.Duration
	IdleTimeout           time.Duration
}

// NewCloudCode builds the family. An empty ID is rejected.
func NewCloudCode(opts CloudCodeOptions) (*CloudCode, error) {
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
		desc.Protocol = contracts.WireCloudCode
	}
	modes := opts.AuthModes
	if len(modes) == 0 {
		modes = []contracts.AuthMode{contracts.AuthOAuth}
	}
	models := make(map[domain.ModelID]modelSpec, len(opts.Models))
	for name, mc := range opts.Models {
		models[name] = modelSpec{caps: mc.Capabilities, mods: mc.Modalities}
	}
	return &CloudCode{
		id:       opts.ID,
		desc:     desc,
		models:   models,
		authMode: modes,
		baseURL:  opts.BaseURL,
		allowLo:  opts.AllowLoopback,
		ttft:     opts.ResponseHeaderTimeout,
		idle:     opts.IdleTimeout,
	}, nil
}

// ID implements contracts.ProviderFamily.
func (f *CloudCode) ID() domain.ProviderID { return f.id }

// AuthModes implements contracts.ProviderFamily.
func (f *CloudCode) AuthModes() []contracts.AuthMode {
	out := make([]contracts.AuthMode, len(f.authMode))
	copy(out, f.authMode)
	return out
}

// Protocol implements contracts.ProviderFamily.
func (f *CloudCode) Protocol() contracts.WireFormat { return f.desc.Protocol }

// Descriptor returns the static descriptor (with its obfuscation layer).
func (f *CloudCode) Descriptor() contracts.ProviderDescriptor { return f.desc }

// Capabilities implements contracts.ProviderFamily.
func (f *CloudCode) Capabilities(model domain.ModelID) (contracts.Capabilities, bool) {
	spec, ok := f.models[model]
	if !ok {
		return 0, false
	}
	return spec.caps, true
}

// Modalities reports a model's modalities.
func (f *CloudCode) Modalities(model domain.ModelID) (contracts.ModalitySet, bool) {
	spec, ok := f.models[model]
	if !ok {
		return 0, false
	}
	return spec.mods, true
}

// Models returns the declared models in deterministic order.
func (f *CloudCode) Models() []domain.ModelID {
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

// BuildExecutor implements contracts.ProviderFamily: it builds the CloudCode
// transport+auth executor. A credential from another family, a missing base URL
// or an unsupported auth mode is refused (typed).
func (f *CloudCode) BuildExecutor(cred contracts.Credential, deps contracts.ExecutorDeps) (contracts.Executor, error) {
	if cred.Provider != f.id {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"reason": "credential provider " + string(cred.Provider) + " does not match family " + string(f.id),
			}),
		)
	}
	if !f.supportsAuthMode(cred.AuthMode) {
		return nil, domain.New(domain.CodeProviderAuthModeUnsupported,
			domain.WithHTTPStatus(500),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"provider": string(f.id), "mode": cred.AuthMode.String()}),
		)
	}
	return cloudcode.New(cloudcode.Config{
		Family:                f.id,
		BaseURL:               f.baseURL,
		AllowLoopback:         f.allowLo,
		ResponseHeaderTimeout: f.ttft,
		IdleTimeout:           f.idle,
		Descriptor:            f.desc,
	}, deps)
}

// supportsAuthMode reports whether the family declares the credential's mode.
func (f *CloudCode) supportsAuthMode(mode contracts.AuthMode) bool {
	for _, m := range f.authMode {
		if m == mode {
			return true
		}
	}
	return false
}
