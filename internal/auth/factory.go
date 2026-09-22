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
	// registry maps provider -> allowed auth modes, so a flow is only built for
	// a mode the provider actually supports.
	modes map[domain.ProviderID][]contracts.AuthMode
}

// NewFlowFactory builds the factory over the F1 descriptors.
func NewFlowFactory(deps oauth.ClientDeps) *FlowFactory {
	return &FlowFactory{
		deps:        deps,
		descriptors: Descriptors(),
		modes: map[domain.ProviderID][]contracts.AuthMode{
			ProviderAntigravity: {contracts.AuthOAuth},
			ProviderZAI:         {contracts.AuthAPIKey},
			ProviderOllamaCloud: {contracts.AuthAPIKey},
			ProviderCommandCode: {contracts.AuthAPIKey},
		},
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
	if fields := pendingFields(PendingEndpoints(), provider); len(fields) > 0 {
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
		// A device flow is preferred when a device endpoint exists; otherwise
		// the PKCE flow (Antigravity currently declares both placeholders, and
		// device is tried first).
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
