package auth

import (
	"sort"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// pendingFields returns the unconfirmed fields for a provider, or nil when it
// has none. It is exported as a helper so the CLI can report the same list the
// factory uses to refuse.
func pendingFields(pending map[domain.ProviderID][]string, provider domain.ProviderID) []string {
	return pending[provider]
}

// PendingFields is the exported form of pendingFields for the CLI.
func PendingFields(provider domain.ProviderID) []string {
	return pendingFields(PendingEndpoints(), provider)
}

// FlowFactory builds the AuthFlow for a provider/auth-mode pair. It is the seam
// the composition root and the CLI use: they know a provider id and a mode, the
// factory knows which concrete flow and which descriptor to bind.
type FlowFactory struct {
	deps        oauth.ClientDeps
	descriptors map[domain.ProviderID]contracts.ProviderDescriptor
	// secrets holds the per-provider OAuth client secrets supplied by the
	// operator (config/env). They are INJECTED here, never hardcoded in the
	// descriptors: a secret literal in source is a secret-scanning hazard and
	// must never ship in the repo (see NewFlowFactoryWithSecrets). A provider
	// whose descriptor declares RequiresClientSecret and has no entry here
	// fails closed in Build.
	secrets map[domain.ProviderID]string
	// registry maps provider -> allowed auth modes, so a flow is only built for
	// a mode the provider actually supports.
	modes map[domain.ProviderID][]contracts.AuthMode
	// pending is the set of providers with unconfirmed endpoints. It is a field
	// (seeded from PendingEndpoints) so the refusal is testable without
	// re-flagging a real descriptor.
	pending map[domain.ProviderID][]string
}

// NewFlowFactory builds the factory over the F1 descriptors WITHOUT any OAuth
// client secrets. A provider that needs one (Antigravity) will fail closed in
// Build; production uses NewFlowFactoryWithSecrets to inject them from config.
func NewFlowFactory(deps oauth.ClientDeps) *FlowFactory {
	return NewFlowFactoryWithSecrets(deps, nil)
}

// NewFlowFactoryWithSecrets builds the factory and injects the operator-supplied
// per-provider OAuth client secrets. The secrets come from configuration (a
// direct value or a named env var), never from a hardcoded literal. A nil/empty
// map is valid: any provider that requires a secret then fails closed in Build.
//
// The map is COPIED, so a later mutation by the caller cannot change what a
// built flow uses.
func NewFlowFactoryWithSecrets(deps oauth.ClientDeps, secrets map[domain.ProviderID]string) *FlowFactory {
	injected := make(map[domain.ProviderID]string, len(secrets))
	for k, v := range secrets {
		if v != "" {
			injected[k] = v
		}
	}
	return &FlowFactory{
		deps:        deps,
		descriptors: Descriptors(),
		secrets:     injected,
		modes: map[domain.ProviderID][]contracts.AuthMode{
			ProviderAntigravity: {contracts.AuthOAuth},
			ProviderZAI:         {contracts.AuthAPIKey},
			ProviderOllamaCloud: {contracts.AuthAPIKey},
			ProviderCommandCode: {contracts.AuthAPIKey},
		},
		pending: PendingEndpoints(),
	}
}

// Build returns the AuthFlow for a provider using its preferred mode. It
// prefers OAuth when available (Antigravity) and falls back to APIKey.
//
// A provider whose endpoints are still placeholders is REFUSED with an explicit
// code (auth.provider_pending_endpoints): building a flow that can only fail
// against the live service would be a silent trap. Callers that need the
// descriptor for offline inspection use Descriptor directly.
func (f *FlowFactory) Build(provider domain.ProviderID) (contracts.AuthFlow, error) {
	desc, ok := f.descriptors[provider]
	if !ok {
		return nil, domain.New(domain.CodeProviderNotFound,
			domain.WithHTTPStatus(404),
			domain.WithParams(map[string]string{"provider": string(provider)}),
		)
	}
	if fields := pendingFields(f.pending, provider); len(fields) > 0 {
		return nil, domain.New(domain.CodeAuthProviderPending,
			domain.WithHTTPStatus(501),
			domain.WithParams(map[string]string{
				"provider": string(provider),
				"fields":   strings.Join(fields, ", "),
			}),
		)
	}
	modes := f.modes[provider]
	if len(modes) == 0 {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "provider has no auth mode"}),
		)
	}
	// Prefer OAuth, then APIKey, then None.
	preferred := modes[0]
	for _, m := range modes {
		if m == contracts.AuthOAuth {
			preferred = m
			break
		}
	}

	switch preferred {
	case contracts.AuthOAuth:
		// A provider whose descriptor declares a client secret gets the
		// Antigravity-style flow: authorization_code WITH the public
		// client_secret plus the post-exchange (project/tier discovery and
		// onboarding). A device endpoint takes precedence when present,
		// otherwise the generic PKCE flow.
		if desc.RequiresClientSecret {
			secret := f.secrets[provider]
			if secret == "" {
				// Fail closed: the secret is not bundled and the operator did
				// not supply it. Running with a placeholder would send a bogus
				// client_secret to the provider and fail opaquely; refuse with
				// a typed, actionable code instead.
				return nil, domain.New(domain.CodeAuthProviderClientSecretMissing,
					domain.WithHTTPStatus(400),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"provider": string(provider)}),
				)
			}
			// Bind the injected secret onto a COPY of the descriptor, so the
			// package-level descriptor map is never mutated and a second call
			// sees the same state.
			desc.ClientSecret = secret
			return oauth.NewAntigravityFlow(f.deps, desc, oauth.DefaultAntigravityConfig()), nil
		}
		if desc.DeviceAuthEndpoint != "" {
			return oauth.NewDeviceCodeFlow(f.deps, desc), nil
		}
		return oauth.NewPKCEFlow(f.deps, desc), nil
	case contracts.AuthAPIKey:
		return NewAPIKeyFlow(provider, f.deps.Clock), nil
	default:
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "unsupported auth mode"}),
		)
	}
}

// AuthModes returns the auth modes a provider supports, in preference order.
// It is the single source of truth the registry also uses when constructing a
// family, so `provider list` cannot disagree with what Build will accept.
func (f *FlowFactory) AuthModes(provider domain.ProviderID) []contracts.AuthMode {
	return f.modes[provider]
}

// AuthModesFor is the package-level form of FlowFactory.AuthModes, for callers
// that build a family before a factory exists.
func AuthModesFor(provider domain.ProviderID) []contracts.AuthMode {
	switch provider {
	case ProviderAntigravity:
		return []contracts.AuthMode{contracts.AuthOAuth}
	case ProviderZAI, ProviderOllamaCloud, ProviderCommandCode:
		return []contracts.AuthMode{contracts.AuthAPIKey}
	default:
		return nil
	}
}

// Providers returns the known provider IDs in deterministic order.
func (f *FlowFactory) Providers() []domain.ProviderID {
	ids := make([]string, 0, len(f.descriptors))
	for id := range f.descriptors {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	out := make([]domain.ProviderID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.ProviderID(id))
	}
	return out
}
