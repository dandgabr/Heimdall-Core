package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// CredentialStore is the SQLite implementation of contracts.CredentialStore.
//
// It persists credential METADATA plus the already-sealed secret blob. It never
// sees plaintext: the caller runs SecretStore.Seal before Upsert and the
// Executor runs Open after Get. The column secret_blob holds only the enc:v1
// envelope, which is what makes "the DB copied without the KEK is unreadable"
// true at the storage layer.
//
// Concurrency: reads go through the read pool; mutations go through the single
// writer connection (store.go). RefreshLock adds the per-credential
// application-level serialization the pool cannot provide (ADR-0001: two
// goroutines refreshing the SAME credential must collapse into one exchange).
type CredentialStore struct {
	store *Store
	locks *lockRegistry
}

// NewCredentialStore builds the store over an open vault.
func NewCredentialStore(s *Store) *CredentialStore {
	return &CredentialStore{store: s, locks: newLockRegistry()}
}

// compile-time assertion that the concrete store satisfies the frozen contract.
var _ contracts.CredentialStore = (*CredentialStore)(nil)

// List returns every credential, newest first. Safe for concurrent use.
func (c *CredentialStore) List(ctx context.Context) ([]contracts.Credential, error) {
	rows, err := c.store.read.QueryContext(ctx, `
		SELECT id, provider, auth_mode, label, meta, secret_blob, created_at, updated_at, expires_at
		FROM credentials ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, credentialError("list", err)
	}
	defer rows.Close()

	var out []contracts.Credential
	for rows.Next() {
		cred, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, credentialError("list", err)
	}
	return out, nil
}

// Get returns one credential or contracts.ErrNotFound.
func (c *CredentialStore) Get(ctx context.Context, id domain.CredentialID) (contracts.Credential, error) {
	row := c.store.read.QueryRowContext(ctx, `
		SELECT id, provider, auth_mode, label, meta, secret_blob, created_at, updated_at, expires_at
		FROM credentials WHERE id = ?`, string(id))

	cred, err := scanCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.Credential{}, contracts.ErrNotFound
	}
	if err != nil {
		return contracts.Credential{}, err
	}
	return cred, nil
}

// Upsert inserts or replaces a credential. Sealed must already be the
// SecretStore output; an empty Sealed is accepted only for AuthNone.
func (c *CredentialStore) Upsert(ctx context.Context, cred contracts.Credential) error {
	if cred.ID == "" {
		return credentialError("upsert", errors.New("credential id is empty"))
	}
	if len(cred.Sealed) == 0 && cred.AuthMode != contracts.AuthNone {
		return domain.New(domain.CodeCredentialStoreFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "sealed secret is empty for a credential that needs one"}),
		)
	}
	// FAIL-CLOSED on format: a non-empty Sealed MUST be a well-formed enc:v1
	// envelope. This is the last line of defence against persisting plaintext:
	// the caller is supposed to seal first, but if it passes a raw token the
	// store rejects it here instead of writing it to disk. ParseEnvelope is the
	// strict parser (prefix, version, IV/tag lengths, blob version), so a
	// truncated or hand-rolled blob is refused too.
	if len(cred.Sealed) > 0 {
		if _, err := secret.ParseEnvelope(string(cred.Sealed)); err != nil {
			return domain.New(domain.CodeCredentialStoreFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(err),
				domain.WithParams(map[string]string{
					"reason": "sealed secret is not a valid enc:v1 envelope; refusing to persist plaintext",
				}),
			)
		}
	}
	if !validAuthMode(cred.AuthMode) {
		return domain.New(domain.CodeCredentialInvalidAuthMode,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"id":   string(cred.ID),
				"mode": fmt.Sprintf("%d", cred.AuthMode),
			}),
		)
	}

	metaJSON, err := json.Marshal(cred.Meta)
	if err != nil {
		return credentialError("upsert", err)
	}
	now := time.Now().UTC()
	created := cred.CreatedAt.UTC()
	if cred.CreatedAt.IsZero() {
		created = now
	}

	_, err = c.store.write.ExecContext(ctx, `
		INSERT INTO credentials (id, provider, auth_mode, label, meta, secret_blob, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			provider    = excluded.provider,
			auth_mode   = excluded.auth_mode,
			label       = excluded.label,
			meta        = excluded.meta,
			secret_blob = excluded.secret_blob,
			updated_at  = excluded.updated_at,
			expires_at  = excluded.expires_at`,
		string(cred.ID),
		string(cred.Provider),
		cred.AuthMode.String(),
		cred.Label,
		string(metaJSON),
		string(cred.Sealed),
		formatTime(created),
		formatTime(now),
		formatTime(cred.ExpiresAt),
	)
	if err != nil {
		return credentialError("upsert", err)
	}
	return nil
}

// Delete removes a credential and its cascade state.
func (c *CredentialStore) Delete(ctx context.Context, id domain.CredentialID) error {
	res, err := c.store.write.ExecContext(ctx, `DELETE FROM credentials WHERE id = ?`, string(id))
	if err != nil {
		return credentialError("delete", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return contracts.ErrNotFound
	}
	return nil
}

// RefreshLock acquires the single-flight lock for one credential. See the
// contract comment in internal/contracts/credential_store.go for the invariant.
//
// The returned unlock is idempotent (sync.Once) and the wait honours ctx: a
// cancelled wait returns credential.refresh_wait_cancelled rather than blocking.
func (c *CredentialStore) RefreshLock(ctx context.Context, id domain.CredentialID) (func(), error) {
	release, err := c.locks.acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	return release, nil
}

// --- row scanning ---

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredential(s rowScanner) (contracts.Credential, error) {
	var (
		id, provider, authMode, label, meta, secret, created, updated, expires string
	)
	if err := s.Scan(&id, &provider, &authMode, &label, &meta, &secret, &created, &updated, &expires); err != nil {
		return contracts.Credential{}, err
	}

	mode, err := parseAuthMode(authMode)
	if err != nil {
		return contracts.Credential{}, domain.New(domain.CodeCredentialInvalidAuthMode,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"id": id, "mode": authMode}),
		)
	}

	var accountMeta contracts.AccountMeta
	if meta != "" {
		if err := json.Unmarshal([]byte(meta), &accountMeta); err != nil {
			return contracts.Credential{}, credentialError("decode meta", err)
		}
	}

	return contracts.Credential{
		ID:        domain.CredentialID(id),
		Provider:  domain.ProviderID(provider),
		AuthMode:  mode,
		Label:     label,
		Meta:      accountMeta,
		Sealed:    []byte(secret),
		CreatedAt: parseTime(created),
		ExpiresAt: parseTime(expires),
	}, nil
}

// --- helpers ---

func validAuthMode(m contracts.AuthMode) bool {
	switch m {
	case contracts.AuthNone, contracts.AuthAPIKey, contracts.AuthOAuth:
		return true
	default:
		return false
	}
}

// parseAuthMode reverses AuthMode.String() via the shared contract parser, so
// the store and the importer cannot drift on the vocabulary.
func parseAuthMode(s string) (contracts.AuthMode, error) {
	mode, ok := contracts.ParseAuthMode(s)
	if !ok {
		return contracts.AuthNone, fmt.Errorf("unknown auth mode %q", s)
	}
	return mode, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func credentialError(op string, err error) error {
	return domain.New(domain.CodeCredentialStoreFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": op + ": " + err.Error()}),
	)
}

// --- per-credential single-flight lock ---

// lockRegistry hands out one semaphore per CredentialID and reclaims it when
// the last holder/waiters leaves, so the map does not grow without bound.
type lockRegistry struct {
	mu    sync.Mutex
	locks map[domain.CredentialID]*lockEntry
}

type lockEntry struct {
	// sem has capacity 1: a send acquires, a receive releases.
	sem chan struct{}
	// refs counts holders AND waiters; the entry is removed at zero.
	refs int
}

func newLockRegistry() *lockRegistry {
	return &lockRegistry{locks: make(map[domain.CredentialID]*lockEntry)}
}

// acquire blocks until the per-id semaphore is free or ctx is done.
func (r *lockRegistry) acquire(ctx context.Context, id domain.CredentialID) (func(), error) {
	entry := r.ref(id)
	select {
	case entry.sem <- struct{}{}:
		// acquired
	case <-ctx.Done():
		r.releaseRef(id, entry)
		return nil, domain.New(domain.CodeCredentialRefreshWait,
			domain.WithHTTPStatus(408),
			domain.WithCause(ctx.Err()),
			domain.WithParams(map[string]string{"id": string(id)}),
		)
	}
	return r.unlockFunc(id, entry), nil
}

// ref returns the entry for id, creating it and incrementing its refcount.
func (r *lockRegistry) ref(id domain.CredentialID) *lockEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.locks[id]
	if !ok {
		entry = &lockEntry{sem: make(chan struct{}, 1)}
		r.locks[id] = entry
	}
	entry.refs++
	return entry
}

// unlockFunc returns the idempotent release closure.
func (r *lockRegistry) unlockFunc(id domain.CredentialID, entry *lockEntry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			// Free the semaphore, then drop this holder's reference. The drain
			// must happen while refs still counts this holder so a concurrent
			// ref() cannot observe refs==0 and delete the entry mid-release.
			<-entry.sem
			r.releaseRef(id, entry)
		})
	}
}

// releaseRef decrements the refcount and removes the entry at zero.
func (r *lockRegistry) releaseRef(id domain.CredentialID, entry *lockEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry.refs--
	if entry.refs <= 0 {
		// Only remove if it is still the same entry (a racing ref could have
		// replaced it after a zero-ref delete, which cannot happen while we
		// hold mu, but the identity check keeps the invariant explicit).
		if current, ok := r.locks[id]; ok && current == entry {
			delete(r.locks, id)
		}
	}
}
