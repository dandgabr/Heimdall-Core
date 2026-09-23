// Package domain holds the leaf value types of Heimdall Core.
//
// It deliberately imports nothing from other internal packages so that every
// other package may depend on it without risking an import cycle.
package domain

import "github.com/google/uuid"

// ProviderID identifies a provider family (the protocol implementation), not a
// specific account. See CredentialID for the account.
type ProviderID string

// CredentialID identifies one stored account/credential of a provider family.
type CredentialID string

// ClientID identifies one downstream client key issued for the inference
// gateway (/v1/*). It is the NON-SECRET identity the boundary injects after
// authenticating a client key (ADR-SEC-06 §2.5); the key's plaintext never
// leaves the authentication step.
type ClientID string

// ComboID identifies a named, persisted routing combo.
type ComboID string

// RequestID is a time-sortable identifier used for correlation.
type RequestID string

// ModelID is the upstream model name.
type ModelID string

// NewRequestID returns a UUIDv7, which is time-sortable and therefore keeps
// log/observability ordering stable under concurrency.
func NewRequestID() RequestID {
	return RequestID(uuid.Must(uuid.NewV7()).String())
}

// NewCredentialID returns a UUIDv7 credential identifier.
func NewCredentialID() CredentialID {
	return CredentialID(uuid.Must(uuid.NewV7()).String())
}

func (r RequestID) String() string    { return string(r) }
func (c CredentialID) String() string { return string(c) }
func (p ProviderID) String() string   { return string(p) }
func (c ClientID) String() string     { return string(c) }
