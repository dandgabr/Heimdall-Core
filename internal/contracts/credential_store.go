package contracts

import (
	"context"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the credential persistence contract of F1. The concrete
// implementation (SQLite + SecretStore) lands in F1.3, owned by another agent.
//
// CredentialStore is the transactional boundary for credential METADATA plus
// the sealed secret blob. It never sees plaintext: the caller seals before
// Upsert and the Executor opens after Get. The store is the ONLY component that
// serializes refresh per credential (RefreshLock).

// ErrNotFound is returned by Get when the credential does not exist. It is a
// sentinel so callers use errors.Is instead of string comparison.
var ErrNotFound = domain.New(domain.CodeNotFound,
	domain.WithHTTPStatus(404),
)

// CredentialStore persists credentials and serializes per-credential refresh.
//
// Single-writer note (ADR-010): the SQLite layer funnels mutations through one
// connection (internal/store), so Upsert/Delete are serialized at the pool.
// RefreshLock adds the per-credential application-level lock that the pool does
// NOT provide: two goroutines refreshing the SAME credential must collapse into
// one upstream exchange.
type CredentialStore interface {
	// List returns every stored credential. It is read-only and safe to call
	// concurrently.
	List(ctx context.Context) ([]Credential, error)
	// Get returns one credential, or ErrNotFound.
	Get(ctx context.Context, id domain.CredentialID) (Credential, error)
	// Upsert inserts or replaces a credential. Sealed must already contain the
	// SecretStore output; an empty Sealed is valid only for AuthNone.
	Upsert(ctx context.Context, cred Credential) error
	// Delete removes a credential and its sealed blob.
	Delete(ctx context.Context, id domain.CredentialID) error

	// RefreshLock acquires the single-flight lock for one credential and
	// returns the function that releases it. The caller MUST defer unlock.
	//
	// INVARIANT — single-flight: for a given CredentialID, at most ONE holder
	// exists at a time; concurrent callers block until the holder unlocks, then
	// proceed. A correct implementation lets the second caller observe the
	// first one's persisted result instead of refreshing again: the canonical
	// pattern is that each caller re-reads the credential via Get after
	// acquiring the lock and skips Refresh if ExpiresAt has moved past now.
	// RefreshLock must respect ctx: a cancelled wait returns ctx.Err() (wrapped
	// as a DomainError) rather than blocking forever, and the unlock function is
	// idempotent.
	RefreshLock(ctx context.Context, id domain.CredentialID) (unlock func(), err error)
}
