// Package mgmt exposes the local Management API consumed by the web GUI and
// the CLI.
//
// # Trust model (ADR-SEC-06)
//
// Every route under /api/mgmt/ is a MUTATION-class route in the ADR's taxonomy:
// it always runs behind the catch-all middleware.LocalOnly, and every route
// requires the management token. The handler mounts a single authenticated
// sub-mux under the "/api/mgmt/" subtree, so a route added later inherits the
// token guard BY CONSTRUCTION — the same catch-all discipline LocalOnly uses.
//
// # No secrets on the wire
//
// The wire DTOs in this file have NO field that can hold a sealed blob, a key
// hash or a client key. A handler therefore cannot serialize a secret even by
// accident; the only two deliberate one-time reveals (the rotated management
// token and a newly created client key) return a dedicated field on a dedicated
// response, marked no-store and never logged.
package mgmt

import (
	"context"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Service is the management surface the HTTP handler needs. It is implemented
// by the composition root (internal/app), which owns the vault, the routing
// layer and the gate chain. Defining the port here — the consumer — keeps this
// package free of the app and its dependencies (the anti-cycle rule).
//
// Every return value is a wire DTO with no secret field, so the boundary
// between the service and the wire is where the "no secret" guarantee is made
// structural rather than a convention.
type Service interface {
	// Status is the aggregate health snapshot.
	Status(ctx context.Context) (StatusView, error)
	// Providers lists the registered families and their honest readiness.
	Providers(ctx context.Context) ([]ProviderView, error)
	// ProviderTest probes one provider end to end (no secret in the result).
	ProviderTest(ctx context.Context, id domain.ProviderID) (ProviderTestView, error)
	// Credentials lists the stored credentials WITHOUT their sealed secrets.
	Credentials(ctx context.Context) ([]CredentialView, error)
	// AddCredential seals an API key and stores it; it never echoes the key.
	AddCredential(ctx context.Context, req AddCredentialRequest) (CredentialView, error)
	// DeleteCredential removes a stored credential by id.
	DeleteCredential(ctx context.Context, id domain.CredentialID) error
	// Combos lists the persisted combos.
	Combos(ctx context.Context) ([]ComboView, error)
	// CreateCombo validates and persists a combo (create or replace).
	CreateCombo(ctx context.Context, req ComboRequest) (ComboView, error)
	// DeleteCombo removes a combo by name.
	DeleteCombo(ctx context.Context, id domain.ComboID) error
	// Quotas reports the per-credential quota windows (no secret).
	Quotas(ctx context.Context) ([]QuotaView, error)
	// Gates reports the effective gate chain and its DAG order per stage.
	Gates(ctx context.Context) (GatesView, error)
	// Usage reports aggregate accounting from the durable attempt log.
	Usage(ctx context.Context) (UsageView, error)
	// RotateToken issues a new management token, writes it to the 0600 token
	// file and returns the plaintext EXACTLY ONCE (the caller must not persist
	// it in a reusable place; the handler marks the response no-store).
	RotateToken(ctx context.Context) (TokenRotateView, error)
	// ClientKeys lists the issued client keys WITHOUT their hashes.
	ClientKeys(ctx context.Context) ([]ClientKeyView, error)
	// CreateClientKey issues a client key and returns the plaintext EXACTLY
	// ONCE.
	CreateClientKey(ctx context.Context, label string) (ClientKeyCreatedView, error)
	// RevokeClientKey revokes a client key by id.
	RevokeClientKey(ctx context.Context, id domain.ClientID) error
}

// --- read views ---

// StatusView is GET /api/mgmt/status.
type StatusView struct {
	Version       string   `json:"version"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	Providers     int      `json:"providers"`
	Combos        int      `json:"combos"`
	Credentials   int      `json:"credentials"`
	ClientKeys    int      `json:"client_keys"`
	Gates         []string `json:"gates"`
}

// ProviderView is one row of GET /api/mgmt/providers. It mirrors the CLI's
// `provider list` row (id, protocol, auth modes, readiness, pending, risk).
type ProviderView struct {
	ID               string   `json:"id"`
	Protocol         string   `json:"protocol"`
	AuthModes        []string `json:"auth_modes"`
	PendingEndpoints []string `json:"pending_endpoints,omitempty"`
	Ready            bool     `json:"ready"`
	ReasonCode       string   `json:"reason_code,omitempty"`
	Future           bool     `json:"future"`
	RiskNotice       string   `json:"risk_notice,omitempty"`
}

// ProviderTestView is the result of POST /api/mgmt/providers/{id}/test. It
// carries no secret: the credential is referenced by id only.
type ProviderTestView struct {
	Provider     string `json:"provider"`
	CredentialID string `json:"credential_id,omitempty"`
	Status       int    `json:"status"`
}

// CredentialView is one row of GET /api/mgmt/credentials. It has NO sealed
// field: the secret is structurally absent from the wire shape.
type CredentialView struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	AuthMode  string `json:"auth_mode"`
	Label     string `json:"label"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// AddCredentialRequest is the body of POST /api/mgmt/credentials. Key is the
// plaintext API key: it is sealed immediately and never echoed or logged.
type AddCredentialRequest struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Key      string `json:"key"`
}

// ComboStepView is one step of a combo on the wire.
type ComboStepView struct {
	Kind      string   `json:"kind"`
	Ref       string   `json:"ref"`
	Weight    int      `json:"weight,omitempty"`
	Prompt    string   `json:"prompt,omitempty"`
	Allowed   []string `json:"allowed_connections,omitempty"`
	QuotaOnly bool     `json:"fallback_only_on_quota,omitempty"`
}

// ComboView is one row of GET /api/mgmt/combos.
type ComboView struct {
	Name     string          `json:"name"`
	Strategy string          `json:"strategy"`
	Steps    []ComboStepView `json:"steps"`
	Depth    int             `json:"depth"`
}

// ComboRequest is the body of POST /api/mgmt/combos.
type ComboRequest struct {
	Name     string          `json:"name"`
	Strategy string          `json:"strategy"`
	Steps    []ComboStepView `json:"steps"`
}

// QuotaWindowView is one window of a credential.
type QuotaWindowView struct {
	Kind      string  `json:"kind"`
	Limit     float64 `json:"limit"`
	Used      float64 `json:"used"`
	Remaining float64 `json:"remaining"`
	ResetsAt  string  `json:"resets_at,omitempty"`
	Source    string  `json:"source"`
}

// QuotaView is one row of GET /api/mgmt/quotas.
type QuotaView struct {
	Credential   string            `json:"credential"`
	Provider     string            `json:"provider,omitempty"`
	TerminalCode string            `json:"terminal_code,omitempty"`
	Windows      []QuotaWindowView `json:"windows"`
}

// GateView is one effective gate, without its content or state.
type GateView struct {
	ID            string   `json:"id"`
	Stages        []string `json:"stages"`
	FailurePolicy string   `json:"failure_policy"`
	RequiredCaps  uint64   `json:"required_caps"`
}

// GatesView is GET /api/mgmt/gates: the effective chain per stage, in the
// dependency-derived (DAG) order it executes in.
type GatesView struct {
	PreRequest      []GateView `json:"pre_request"`
	OnResponseChunk []GateView `json:"on_response_chunk"`
	PostResponse    []GateView `json:"post_response"`
}

// UsageAggView is one rollup row (a provider or a credential key).
type UsageAggView struct {
	Key        string `json:"key"`
	Tokens     int    `json:"tokens"`
	Requests   int    `json:"requests"`
	CostMicros int64  `json:"cost_micros"`
	Attempts   int    `json:"attempts"`
}

// UsageView is GET /api/mgmt/usage: aggregate accounting over the durable
// attempt log (ADR-0011 §4). There is no separate rollup table; these numbers
// are summed from `usage_attempts` on read.
type UsageView struct {
	Total        UsageAggView   `json:"total"`
	ByProvider   []UsageAggView `json:"by_provider"`
	ByCredential []UsageAggView `json:"by_credential"`
}

// --- one-time-secret views ---

// TokenRotateView is the response of POST /api/mgmt/token/rotate. Token is the
// new plaintext management token, returned EXACTLY ONCE (like the CLI, which
// writes it to a 0600 file); Path is where that file was written. The handler
// marks this response no-store and never logs the token.
type TokenRotateView struct {
	Token string `json:"token"`
	Path  string `json:"path"`
}

// ClientKeyView is one row of GET /api/mgmt/client-keys: metadata only, no key
// and no hash.
type ClientKeyView struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	CreatedAt string `json:"created_at,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// ClientKeyCreatedView is the response of POST /api/mgmt/client-keys. Key is
// the new plaintext client key, returned EXACTLY ONCE and never stored in
// recoverable form (the vault keeps only its hash).
type ClientKeyCreatedView struct {
	ClientKeyView
	Key string `json:"key"`
}
