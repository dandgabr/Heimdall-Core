package auth

import (
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Provider identifiers for the four F1 providers. They are the ProviderID
// values the registry is keyed by.
const (
	ProviderAntigravity domain.ProviderID = "antigravity"
	ProviderZAI         domain.ProviderID = "z.ai"
	ProviderOllamaCloud domain.ProviderID = "ollama-cloud"
	ProviderCommandCode domain.ProviderID = "command-code"
)

// Descriptors returns the static description of every F1 provider, keyed by ID.
//
// ENDPOINT PROVENANCE — read before trusting a value:
//
// The API-key providers (z.ai, Ollama Cloud, Command Code) need no OAuth
// endpoints, so their descriptors are complete: only the family identity and
// auth mode matter.
//
// Antigravity is the only OAuth provider. Its authorization/token/device
// endpoints were NOT verified against the live service in this task, and the
// brief forbids inventing them. They are therefore declared with the canonical
// Google OAuth placeholder host and marked `TODO(confirm)` below. The FLOW is
// fully tested against an httptest.Server; only the literal URLs are pending
// confirmation by the provider owner before the family is enabled against the
// real service.
func Descriptors() map[domain.ProviderID]contracts.ProviderDescriptor {
	return map[domain.ProviderID]contracts.ProviderDescriptor{
		ProviderAntigravity: {
			ID:          ProviderAntigravity,
			Protocol:    contracts.WireGemini,
			DisplayName: "Antigravity",
			// TODO(confirm): endpoints to be confirmed with the Antigravity
			// maintainers. Placeholders below follow the Google OAuth device
			// flow shape (RFC 8628) and MUST NOT be used against production
			// until verified.
			DeviceAuthEndpoint: "https://oauth2.googleapis.com/device/code",
			AuthEndpoint:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint:      "https://oauth2.googleapis.com/token",
			DefaultScopes:      nil, // TODO(confirm): exact scopes unknown
			// The loopback callback allowlist is the stable URI; the ephemeral
			// port is validated by the bind.
			RedirectAllowlist: []string{"http://127.0.0.1/callback"},
			// TODO(confirm): ClientID is a public OAuth client id and is not
			// known yet. Empty means Begin cannot run against the real service.
			ClientID: "",
		},
		ProviderZAI: {
			ID:          ProviderZAI,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Z.ai",
		},
		ProviderOllamaCloud: {
			ID:          ProviderOllamaCloud,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Ollama Cloud",
		},
		ProviderCommandCode: {
			ID:          ProviderCommandCode,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Command Code",
		},
	}
}

// Descriptor returns one provider's descriptor, or provider.not_found.
func Descriptor(id domain.ProviderID) (contracts.ProviderDescriptor, error) {
	desc, ok := Descriptors()[id]
	if !ok {
		return contracts.ProviderDescriptor{}, domain.New(domain.CodeProviderNotFound,
			domain.WithHTTPStatus(404),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	return desc, nil
}

// PendingEndpoints lists the provider IDs whose endpoints are placeholders
// awaiting confirmation. The composition root must not enable these against the
// live service until this list is empty for them.
func PendingEndpoints() map[domain.ProviderID][]string {
	return map[domain.ProviderID][]string{
		ProviderAntigravity: {
			"DeviceAuthEndpoint", "AuthEndpoint", "TokenEndpoint", "DefaultScopes", "ClientID",
		},
	}
}
