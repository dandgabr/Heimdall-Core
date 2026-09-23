package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ClientKeyBytes is the entropy of a generated client key: 32 bytes = 256 bits,
// the ADR-SEC-06 §2.3 minimum. The key is hex-encoded with a fixed prefix that
// identifies it as a Heimdall client key (and lets an operator tell it apart
// from a management token at a glance).
const ClientKeyBytes = 32

// ClientKeyPrefix is the fixed, non-secret identifier prefixed to every issued
// client key. It is a LABEL, not entropy; the 256 bits live in the hex suffix.
const ClientKeyPrefix = "hmd_live_"

// ClientKey is the NON-SECRET record of an issued client key. The plaintext is
// never part of this struct and never stored: HashedKey (or, at rest, key_hash)
// is all the vault holds (ADR-SEC-06 §2.4).
type ClientKey struct {
	ID        domain.ClientID
	Label     string
	CreatedAt time.Time
	// RevokedAt is the zero time for a live key.
	RevokedAt time.Time
}

// ClientKeyStore persists and verifies client keys. It mirrors the management
// token's storage discipline: hash-only at rest, constant-time comparison on
// verify, and a nil/empty key always fails closed.
type ClientKeyStore struct {
	store *Store
}

// NewClientKeyStore builds the store over an open vault.
func NewClientKeyStore(s *Store) *ClientKeyStore {
	return &ClientKeyStore{store: s}
}

// clientKeyRandReader is the CSPRNG source for key generation. It is a package
// variable so a test can inject a failing reader and cover the entropy-error
// branch; production never changes it.
var clientKeyRandReader io.Reader = rand.Reader

// clientKeyIDGen is the id source for a new key. It is a package variable so a
// test can inject a fixed id; production uses domain.NewRequestID (UUIDv7).
var clientKeyIDGen = func() string { return domain.NewRequestID().String() }

// HashClientKey returns the hex SHA-256 of a presented key. Hashing is the
// storage and comparison form: the vault never holds the recoverable key, and
// two equal keys always produce the same hash for the constant-time compare.
func HashClientKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// newClientKey returns a fresh 256-bit key, prefixed and hex-encoded.
func newClientKey() (string, error) {
	buf := make([]byte, ClientKeyBytes)
	if _, err := io.ReadFull(clientKeyRandReader, buf); err != nil {
		return "", domain.New(domain.CodeClientKeyStoreFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	return ClientKeyPrefix + hex.EncodeToString(buf), nil
}

// Create generates a new client key, persists ONLY its hash and returns the
// plaintext exactly once. The caller (the CLI) prints it and never stores it.
func (c *ClientKeyStore) Create(ctx context.Context, label string) (ClientKey, string, error) {
	plaintext, err := newClientKey()
	if err != nil {
		return ClientKey{}, "", err
	}
	now := time.Now().UTC()
	rec := ClientKey{
		ID:        domain.ClientID(clientKeyIDGen()),
		Label:     label,
		CreatedAt: now,
	}
	_, err = c.store.write.ExecContext(ctx, `
		INSERT INTO client_keys (id, label, key_hash, created_at, revoked_at)
		VALUES (?, ?, ?, ?, '')`,
		string(rec.ID), rec.Label, HashClientKey(plaintext), formatTime(now),
	)
	if err != nil {
		return ClientKey{}, "", clientKeyError("create", err)
	}
	return rec, plaintext, nil
}

// List returns every client key (live and revoked), oldest first. It never
// returns a hash or a plaintext: the record carries only non-secret metadata.
func (c *ClientKeyStore) List(ctx context.Context) ([]ClientKey, error) {
	rows, err := c.store.read.QueryContext(ctx, `
		SELECT id, label, created_at, revoked_at
		FROM client_keys ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, clientKeyError("list", err)
	}
	defer rows.Close()

	var out []ClientKey
	for rows.Next() {
		rec, err := scanClientKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, clientKeyError("list", err)
	}
	return out, nil
}

// Revoke soft-deletes a key by setting revoked_at (idempotent: revoking an
// already-revoked key reports the row was found and changes nothing).
// ErrNotFound is returned for an unknown id.
func (c *ClientKeyStore) Revoke(ctx context.Context, id domain.ClientID) error {
	res, err := c.store.write.ExecContext(ctx, `
		UPDATE client_keys SET revoked_at = ?
		WHERE id = ? AND revoked_at = ''`,
		formatTime(time.Now().UTC()), string(id),
	)
	if err != nil {
		return clientKeyError("revoke", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Either the id does not exist or it was already revoked. Distinguish
		// so the CLI can report an unknown id (fail-closed) rather than a
		// silent success.
		exists, gerr := c.exists(ctx, id)
		if gerr != nil {
			return gerr
		}
		if !exists {
			return contractsNotFound(id)
		}
		return nil // already revoked: idempotent success
	}
	return nil
}

// exists reports whether a client key row with id exists (live or revoked).
func (c *ClientKeyStore) exists(ctx context.Context, id domain.ClientID) (bool, error) {
	var one int
	err := c.store.read.QueryRowContext(ctx,
		`SELECT 1 FROM client_keys WHERE id = ?`, string(id)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, clientKeyError("exists", err)
	}
	return true, nil
}

// Verify authenticates a presented key in constant time and returns the
// matching live key's non-secret identity. A malformed, unknown or REVOKED key
// returns (ClientKey{}, false); an internal read failure also returns false
// (fail-closed) — an unreadable vault must never admit a request.
//
// The lookup is by hash (an indexed, UNIQUE column), then the hash comparison
// is constant-time. The plaintext is never logged and never returned.
func (c *ClientKeyStore) Verify(ctx context.Context, presented string) (ClientKey, bool) {
	if presented == "" {
		return ClientKey{}, false
	}
	rec, storedHash, revoked, err := c.lookup(ctx, HashClientKey(presented))
	if err != nil || storedHash == "" {
		return ClientKey{}, false
	}
	// Constant-time compare of the stored hash against the presented hash. The
	// lookup by hash already implies equality, but this is the explicit
	// guarantee (ADR-SEC-06 §2.4/§7.10) and protects against a future
	// non-indexed strategy change.
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(HashClientKey(presented))) != 1 {
		return ClientKey{}, false
	}
	if revoked {
		return ClientKey{}, false
	}
	return rec, true
}

// lookup reads the row matching a hash. It returns the non-secret record, the
// stored hash, and whether the row is revoked. No matching row yields a zero
// record with an empty hash and nil error.
func (c *ClientKeyStore) lookup(ctx context.Context, hash string) (ClientKey, string, bool, error) {
	row := c.store.read.QueryRowContext(ctx, `
		SELECT id, label, created_at, revoked_at, key_hash
		FROM client_keys WHERE key_hash = ?`, hash)
	rec, storedHash, revoked, err := scanClientKeyRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientKey{}, "", false, nil
	}
	if err != nil {
		return ClientKey{}, "", false, clientKeyError("lookup", err)
	}
	return rec, storedHash, revoked, nil
}

// --- row scanning ---

type clientKeyScanner interface {
	Scan(dest ...any) error
}

// scanClientKey reads the metadata rows (no hash column) used by List.
func scanClientKey(s clientKeyScanner) (ClientKey, error) {
	var id, label, created, revoked string
	if err := s.Scan(&id, &label, &created, &revoked); err != nil {
		return ClientKey{}, clientKeyError("scan", err)
	}
	return buildClientKey(id, label, created, revoked)
}

// scanClientKeyRow reads the full row (with the hash) used by lookup.
func scanClientKeyRow(s clientKeyScanner) (ClientKey, string, bool, error) {
	var id, label, created, revoked, hash string
	if err := s.Scan(&id, &label, &created, &revoked, &hash); err != nil {
		return ClientKey{}, "", false, err
	}
	rec, err := buildClientKey(id, label, created, revoked)
	if err != nil {
		return ClientKey{}, "", false, err
	}
	return rec, hash, revoked != "", nil
}

// buildClientKey parses the timestamp columns into the record.
func buildClientKey(id, label, created, revoked string) (ClientKey, error) {
	createdAt, err := parseTime(created)
	if err != nil {
		return ClientKey{}, corruptedKeyTimeError(id, "created_at", created, err)
	}
	revokedAt, err := parseTime(revoked)
	if err != nil {
		return ClientKey{}, corruptedKeyTimeError(id, "revoked_at", revoked, err)
	}
	return ClientKey{
		ID:        domain.ClientID(id),
		Label:     label,
		CreatedAt: createdAt,
		RevokedAt: revokedAt,
	}, nil
}

func corruptedKeyTimeError(id, column, value string, cause error) error {
	return domain.New(domain.CodeClientKeyStoreFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(cause),
		domain.WithParams(map[string]string{
			"reason": "client key " + id + " has a corrupt " + column,
		}),
	)
}

func clientKeyError(op string, err error) error {
	return domain.New(domain.CodeClientKeyStoreFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": op}),
	)
}

// contractsNotFound is a small local helper so the store keeps its own error
// vocabulary (the client-key revoke path) without importing contracts here.
func contractsNotFound(id domain.ClientID) error {
	return domain.New(domain.CodeClientKeyNotFound,
		domain.WithHTTPStatus(404),
		domain.WithParams(map[string]string{"id": string(id)}),
	)
}
