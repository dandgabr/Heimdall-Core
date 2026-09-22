package secret

import (
	"log/slog"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Store is the concrete SecretStore (ADR-SEC-01 §6). It holds the resolved KEK
// in memory for the process lifetime and seals/opens credential fields with the
// enc:v1 envelope. It is the only component that ever sees the KEK.
//
// Fail-closed invariants:
//   - it cannot be constructed without a KEK (New refuses);
//   - Seal and Open return an error, never plaintext, on any failure;
//   - no method ever writes plaintext to disk; the caller persists only Seal's
//     return value.
type Store struct {
	kek []byte
}

// Options configures Store construction.
type Options struct {
	// Salt is the per-installation salt (LoadOrCreateSalt).
	Salt []byte
	// Params are the Argon2id cost parameters (DefaultKDFParams in production).
	Params KDFParams
	// Custody is the layered key source. Its Salt/Params are overwritten by
	// the values here so there is exactly one place they are configured.
	Custody Custody
	// Logger receives custody warnings (never material). Nil means slog.Default.
	Logger *slog.Logger
}

// New resolves the KEK through the custody chain and returns a ready Store. A
// missing key surfaces as config.secret_missing and the caller MUST refuse to
// start (fail-closed); New never falls back to a generated or empty key.
func New(opts Options) (*Store, error) {
	if err := opts.Params.Validate(); err != nil {
		return nil, err
	}
	if len(opts.Salt) != SaltSize {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "salt must be 16 bytes"}),
		)
	}

	custody := opts.Custody
	custody.Salt = opts.Salt
	custody.Params = opts.Params
	if custody.Logger == nil {
		custody.Logger = opts.Logger
	}

	kek, _, err := custody.ResolveKEK()
	if err != nil {
		return nil, err
	}
	return &Store{kek: kek}, nil
}

// NewWithKEK builds a Store from a KEK already in hand. It exists for the
// recovery path (a KEK unwrapped from the recovery passphrase) and for tests
// that must exercise two distinct KEKs against one vault.
func NewWithKEK(kek []byte) (*Store, error) {
	if len(kek) != KEKSize {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "kek is not 32 bytes"}),
		)
	}
	out := make([]byte, KEKSize)
	copy(out, kek)
	return &Store{kek: out}, nil
}

// Seal encrypts plaintext into the persisted enc:v1 envelope.
func (s *Store) Seal(plaintext []byte) (string, error) {
	if s == nil || len(s.kek) == 0 {
		return "", domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	return Seal(s.kek, plaintext)
}

// Open decrypts a persisted enc:v1 envelope. On error it returns nil, never a
// partial plaintext.
func (s *Store) Open(encoded string) ([]byte, error) {
	if s == nil || len(s.kek) == 0 {
		return nil, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	return Open(s.kek, encoded)
}

// Rewrap re-wraps a record's DEK under newKEK, leaving the record ciphertext
// untouched. The caller persists the returned string back on the same record.
// This is the incremental rotation primitive: the format version in the prefix
// is what lets old and new encodings coexist during the migration.
func (s *Store) Rewrap(newKEK []byte, encoded string) (string, error) {
	if s == nil || len(s.kek) == 0 {
		return "", domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	return Rewrap(s.kek, newKEK, encoded)
}

// RotateTo returns a NEW Store bound to newKEK, after verifying that newKEK can
// read a sample record sealed under the current key. The verification is what
// makes rotation safe: a rotation that cannot read its own data is refused
// before anything is mutated. sample may be empty, in which case the check is a
// round-trip against a freshly sealed probe.
func (s *Store) RotateTo(newKEK []byte, sample string) (*Store, error) {
	if s == nil || len(s.kek) == 0 {
		return nil, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	// NewWithKEK is the SINGLE authority on the new KEK's length: it rejects a
	// non-32-byte key up front with the specific error, so RotateTo does not
	// duplicate the check. This is the branch a bad rotation input hits.
	next, err := NewWithKEK(newKEK)
	if err != nil {
		return nil, err
	}

	// Prove the current key can read the sample (or that a fresh probe
	// round-trips), so a rotation never starts from a vault it cannot decrypt.
	probe := sample
	if probe == "" {
		sealed, err := s.Seal([]byte("heimdall-rotation-probe"))
		if err != nil {
			return nil, err
		}
		probe = sealed
	} else if _, err := s.Open(probe); err != nil {
		return nil, err
	}

	// Prove the new key round-trips through the same format before adopting it.
	rewrapped, err := Rewrap(s.kek, newKEK, probe)
	if err != nil {
		return nil, err
	}
	if _, err := next.Open(rewrapped); err != nil {
		return nil, err
	}
	return next, nil
}
