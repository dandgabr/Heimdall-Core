// Package auth implements the AuthFlow contract of F1.5.
//
// Two families of flow live here:
//
//   - APIKeyFlow: a static, contracted key. It performs no network I/O; its job
//     is to validate presence and shape the result the caller seals.
//   - oauth: the interactive grants (device_code per RFC 8628, authorization_code
//     with PKCE S256). The generic flows are transport-injectable so a test can
//     drive them against an httptest.Server with no real network.
//
// Nothing here logs a device_code, an access token or a refresh token. Secrets
// travel as contracts.Secret, which redacts every fmt verb; the one call site
// that needs the bytes uses Reveal().
package auth

import (
	"context"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// APIKeyFlow is the AuthFlow for AuthAPIKey credentials. It is intentionally
// stateless and offline.
type APIKeyFlow struct {
	// Provider is the family the key belongs to, used only for error params.
	Provider domain.ProviderID
	// Clock is the injectable time source (nil means time.Now).
	Clock contracts.Clock
}

// NewAPIKeyFlow builds the flow.
func NewAPIKeyFlow(provider domain.ProviderID, clock contracts.Clock) *APIKeyFlow {
	return &APIKeyFlow{Provider: provider, Clock: clock}
}

// Kind implements contracts.AuthFlow.
func (f *APIKeyFlow) Kind() contracts.AuthMode { return contracts.AuthAPIKey }

// Begin rejects an interactive grant: an API-key credential has no browser
// step. The caller that wants to store a key does so directly (see KeyResult).
func (f *APIKeyFlow) Begin(context.Context, contracts.ProviderDescriptor) (contracts.AuthChallenge, error) {
	return contracts.AuthChallenge{}, domain.New(domain.CodeAuthFlowNotInteractive,
		domain.WithHTTPStatus(400),
		domain.WithParams(map[string]string{"provider": string(f.Provider)}),
	)
}

// Poll is not applicable to a static key.
func (f *APIKeyFlow) Poll(context.Context, contracts.AuthChallenge) (contracts.AuthResult, error) {
	return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowNotInteractive,
		domain.WithHTTPStatus(400),
		domain.WithParams(map[string]string{"provider": string(f.Provider)}),
	)
}

// Refresh for an API key is a no-op that returns the same material: a static key
// does not expire or rotate, so the Dispatcher must never treat it as a retry
// source. It is idempotent by construction.
func (f *APIKeyFlow) Refresh(_ context.Context, cred contracts.Credential, token contracts.RefreshToken) (contracts.AuthResult, error) {
	return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowNotInteractive,
		domain.WithHTTPStatus(400),
		domain.WithParams(map[string]string{"provider": string(f.Provider)}),
	)
}

// KeyResult turns a raw API key into an AuthResult the caller seals. It validates
// presence and shape only; it never contacts the network, so a bad key surfaces
// on first use, not at import time.
func (f *APIKeyFlow) KeyResult(key string, meta contracts.AccountMeta) (contracts.AuthResult, error) {
	if strings.TrimSpace(key) == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthKeyMissing,
			domain.WithHTTPStatus(400),
			domain.WithParams(map[string]string{"provider": string(f.Provider)}),
		)
	}
	if reason := validateKeyShape(key); reason != "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthKeyInvalidFormat,
			domain.WithHTTPStatus(400),
			domain.WithParams(map[string]string{
				"provider": string(f.Provider),
				"reason":   reason,
			}),
		)
	}
	return contracts.AuthResult{
		Access:   contracts.Secret(key),
		AuthMode: contracts.AuthAPIKey,
		Account:  meta,
		// A static key has no known expiry; zero means "unknown / none".
		ExpiresAt: time.Time{},
	}, nil
}

// validateKeyShape performs the offline, provider-independent sanity checks a
// static key must pass before it is stored. It deliberately checks FORMAT only:
// reachability and entitlement require a network round-trip, which is F2's
// egress concern (see ValidateNetwork for the documented seam).
//
// Rejecting a key that is obviously not a key (empty, whitespace, control
// characters, absurdly short) is what keeps the import path from sealing junk.
func validateKeyShape(key string) string {
	if strings.ContainsAny(key, " \t\r\n") {
		return "contains whitespace"
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return "contains control characters"
		}
	}
	if len(key) < minAPIKeyLen {
		return "shorter than the minimum plausible length"
	}
	if len(key) > maxAPIKeyLen {
		return "longer than the maximum plausible length"
	}
	return ""
}

const (
	// minAPIKeyLen is below every key these providers issue but well above a
	// typo or a truncated paste.
	minAPIKeyLen = 8
	// maxAPIKeyLen bounds what we are willing to store.
	maxAPIKeyLen = 4096
)

// ValidateNetwork documents the real, reachability-based validation seam.
//
// NETWORK VALIDATION STATUS (honest, per provider):
//
//   - z.ai, Ollama Cloud, Command Code: their authenticated model-listing
//     endpoints are NOT confirmed in this task, so a network probe is not
//     implemented. Only the offline shape check runs. Adding a probe requires
//     the endpoint to be verified first; inventing one is forbidden.
//
// When an endpoint is confirmed, implement it here as an authenticated GET that
// returns 200 only for a valid key, mapping 401/403 to
// auth.credential_invalid (ScopeCredential, not retryable) per ADR-0002.
//
// This method exists so callers can detect the gap explicitly instead of
// assuming validation happened.
func (f *APIKeyFlow) ValidateNetwork(_ context.Context) (implemented bool, err error) {
	return false, domain.New(domain.CodeAuthProviderPending,
		domain.WithHTTPStatus(501),
		domain.WithParams(map[string]string{
			"provider": string(f.Provider),
			"fields":   "authenticated model-listing endpoint",
		}),
	)
}
