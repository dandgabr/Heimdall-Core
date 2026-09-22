package secret

import (
	"encoding/base64"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// KDF parameters and storage.
//
// Argon2id is the mandated KDF (ADR-SEC-01 §3). It is memory-hard, which is the
// property that matters here: a passphrase is the weakest link in the fallback
// custody layer, and an attacker who copies the vault should not be able to
// brute-force it with a cheap GPU/ASIC loop. The parameters below target
// ~64 MiB and two passes, which is a deliberate cost on a one-shot derivation
// at startup (the KEK is derived once and held in memory), not on the request
// path.

// SaltSize is the per-installation salt length in bytes.
const SaltSize = 16

// DefaultKDFParams are the production parameters. They are documented here so a
// change is a reviewable diff, and they are injectable so tests run cheap.
//
//   - Memory: 64 MiB (65536 KiB) — OWASP's Argon2id recommendation for a
//     memory-constrained server is 19 MiB; a desktop router can afford more.
//   - Time:   2 passes.
//   - Threads: 4 lanes.
//   - KeyLen: 32 bytes (AES-256).
var DefaultKDFParams = KDFParams{
	Memory:  64 * 1024,
	Time:    2,
	Threads: 4,
	KeyLen:  32,
}

// KDFParams are the Argon2id cost parameters.
type KDFParams struct {
	// Memory is in KiB.
	Memory uint32
	// Time is the number of passes.
	Time uint32
	// Threads is the degree of parallelism.
	Threads uint8
	// KeyLen is the derived key length in bytes.
	KeyLen uint32
}

// Validate rejects a zeroed or degenerate parameter set.
//
// KeyLen is checked here, and it MUST be: argon2.IDKey with keyLen == 0 returns
// nil from its blake2b hash and the library then dereferences it, panicking with
// a nil-pointer fault BEFORE any output guard could run. Time < 1 and Threads < 1
// panic inside argon2 for the same reason, so all three preconditions are refused
// at the boundary. A KeyLen other than 32 is also refused because both the KEK
// and the DEK are AES-256.
func (p KDFParams) Validate() error {
	if p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "argon2 parameters must be non-zero"}),
		)
	}
	if p.KeyLen != KEKSize {
		return domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "key length must be 32 bytes"}),
		)
	}
	return nil
}

// NewSalt returns a fresh per-installation salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return nil, wrapRand(err)
	}
	return salt, nil
}

// DeriveKEK runs Argon2id over the layer's secret material with the
// per-installation salt. The raw material is never used as a key directly
// (ADR-SEC-01 §3): a passphrase, a keyring secret and an env override all pass
// through here, so none of them is the key at rest.
func DeriveKEK(material, salt []byte, params KDFParams) ([]byte, error) {
	if len(material) == 0 {
		return nil, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	if len(salt) != SaltSize {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "salt must be 16 bytes"}),
		)
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	kek := deriveKeyFn(material, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	// Defence in depth: Validate already pinned KeyLen == 32, so a correct KDF
	// yields exactly 32 bytes. This guard catches a KDF that returns a different
	// length (e.g. a future swap or a bad KeyLen that slipped past Validate),
	// turning a silently-wrong key into a hard failure.
	if len(kek) != KEKSize {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "derived key is not 32 bytes"}),
		)
	}
	return kek, nil
}

// deriveKeyFn is a seam over argon2.IDKey so the post-derive length guard can be
// exercised with a fake KDF that returns a wrong-length key. The real KDF, with
// KeyLen validated == 32, always returns 32 bytes, so the guard is otherwise
// unreachable.
var deriveKeyFn = argon2.IDKey

// MetaStore is the minimal persistence the salt needs. SetMetaIfAbsent is the
// atomic insert-if-absent primitive that makes load-or-create race-free; it is
// satisfied by *store.Store (which implements it with INSERT ... ON CONFLICT DO
// NOTHING). The interface stays here so this package does not import
// internal/store, which would pull SQLite into the crypto leaf.
type MetaStore interface {
	GetMeta(key string) (value string, found bool, err error)
	SetMeta(key, value string) error
	SetMetaIfAbsent(key, value string) (inserted bool, err error)
}

// SaltMetaKey is the vault meta row holding the base64 per-installation salt.
const SaltMetaKey = "kdf_salt"

// LoadOrCreateSalt reads the installation salt, generating and atomically
// persisting one on first use. Two vaults therefore derive different KEKs from
// the SAME passphrase (ADR-SEC-01, acceptance criterion 4): compromising the
// passphrase of one does not unlock another.
//
// Race safety (P1-3): a plain get-then-set is a TOCTOU. Two concurrent boots both
// observe "no salt", both DERIVE a KEK from their own candidate, and the second
// write overwrites the first — the first process then holds a KEK derived from a
// salt that no longer exists, so any credential it seals becomes undecryptable.
// The fix is to insert-if-absent and then re-read: exactly one candidate wins,
// and every caller (including the loser) derives from the persisted winner.
func LoadOrCreateSalt(meta MetaStore) ([]byte, error) {
	if salt, found, err := readSalt(meta); err != nil {
		return nil, err
	} else if found {
		return salt, nil
	}

	candidate, err := NewSalt()
	if err != nil {
		return nil, err
	}
	encoded := base64.RawStdEncoding.EncodeToString(candidate)

	inserted, err := meta.SetMetaIfAbsent(SaltMetaKey, encoded)
	if err != nil {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot persist " + SaltMetaKey}),
		)
	}
	if inserted {
		return candidate, nil
	}

	// Another caller won the insert. Re-read the persisted value so this caller
	// derives from the SAME salt, not from its discarded candidate.
	salt, found, err := readSalt(meta)
	if err != nil {
		return nil, err
	}
	if !found {
		// The row vanished between the conflict and the re-read: a corrupt or
		// concurrently-wiped vault. Fail closed rather than invent a salt.
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "salt disappeared during load-or-create"}),
		)
	}
	return salt, nil
}

// readSalt decodes the stored salt, validating its length. found=false means the
// row is absent; a malformed value is an error, never silently regenerated.
func readSalt(meta MetaStore) (salt []byte, found bool, err error) {
	encoded, found, err := meta.GetMeta(SaltMetaKey)
	if err != nil {
		return nil, false, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot read " + SaltMetaKey}),
		)
	}
	if !found || encoded == "" {
		return nil, false, nil
	}
	decoded, decodeErr := base64.RawStdEncoding.DecodeString(encoded)
	if decodeErr != nil || len(decoded) != SaltSize {
		return nil, false, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(decodeErr),
			domain.WithParams(map[string]string{"reason": "stored salt is malformed"}),
		)
	}
	return decoded, true, nil
}
