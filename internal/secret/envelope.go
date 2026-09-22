// Package secret implements the encrypted credential vault of F1 (ADR-SEC-01).
//
// Two concerns live here, kept separate on purpose:
//
//   - envelope.go: the persisted ciphertext format enc:v1:<iv>:<ct>:<tag> with
//     AES-256-GCM and per-record DEK/KEK envelope encryption;
//   - custody.go: where the KEK comes from (systemd credential, keyring, 0600
//     key file + passphrase, or an explicit env override), always fail-closed.
//
// The package is a leaf: it imports only internal/domain, the standard library
// and golang.org/x/crypto (pure Go, so CGO_ENABLED=0 is preserved).
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// randReader is the entropy source for every random value in this package (IVs,
// DEKs, salts, PKCE verifiers). It is a package variable so a test can inject a
// failing reader and exercise the crypto/rand error branches, which are
// otherwise unreachable. Production never changes it.
var randReader io.Reader = rand.Reader

// Format constants.
const (
	// prefix is the versioned marker every persisted value carries. A parser
	// that does not recognise it must refuse: an unversioned ciphertext is
	// indistinguishable from plaintext and must never be treated as data.
	prefix = "enc"
	// version is the current format version.
	version = "v1"

	// IVSize is the GCM nonce length in bytes (12, per NIST SP 800-38D).
	IVSize = 12
	// TagSize is the GCM authentication tag length in bytes (16, pinned).
	TagSize = 16
	// DEKSize is the data-encryption key length in bytes (AES-256).
	DEKSize = 32
	// KEKSize is the key-encryption key length in bytes (AES-256).
	KEKSize = 32

	// blobVersion is the inner envelope layout version byte.
	blobVersion byte = 0x01
	// blobMinSize is version(1) + wrappedDEK(32) + recordIV(12) + recordTag(16).
	blobMinSize = 1 + DEKSize + IVSize + TagSize
)

// Envelope is the parsed form of a persisted value. It exposes the parts a
// rotation needs without ever decrypting the record.
type Envelope struct {
	// WrapIV is the IV that wraps the DEK under the KEK.
	WrapIV []byte
	// WrappedDEK is the DEK ciphertext (GCM, verified against WrapTag).
	WrappedDEK []byte
	// WrapTag authenticates the DEK wrap.
	WrapTag []byte
	// RecordIV is the IV of the record encryption under the DEK.
	RecordIV []byte
	// RecordCT is the record ciphertext.
	RecordCT []byte
	// RecordTag authenticates the record.
	RecordTag []byte
}

// Seal encrypts plaintext into the persisted enc:v1 format using envelope
// encryption: a fresh DEK per record encrypts the field, and the KEK wraps the
// DEK. Both layers are AES-256-GCM and therefore authenticated.
func Seal(kek, plaintext []byte) (string, error) {
	if len(kek) != KEKSize {
		return "", domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "kek is not 32 bytes"}),
		)
	}

	// Per-record DEK.
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(randReader, dek); err != nil {
		return "", wrapRand(err)
	}

	recordIV := make([]byte, IVSize)
	if _, err := io.ReadFull(randReader, recordIV); err != nil {
		return "", wrapRand(err)
	}
	recordAEAD, err := newGCMFn(dek)
	if err != nil {
		return "", err
	}
	recordCT := recordAEAD.Seal(nil, recordIV, plaintext, nil)
	// GCM appends the tag to the ciphertext; split it so the layout is explicit
	// and the tag length stays pinned rather than implied.
	recordCT, recordTag := splitTag(recordCT)

	// Wrap the DEK under the KEK.
	wrapIV := make([]byte, IVSize)
	if _, err := io.ReadFull(randReader, wrapIV); err != nil {
		return "", wrapRand(err)
	}
	wrapAEAD, err := newGCMFn(kek)
	if err != nil {
		return "", err
	}
	wrapped := wrapAEAD.Seal(nil, wrapIV, dek, nil)
	wrappedDEK, wrapTag := splitTag(wrapped)

	env := &Envelope{
		WrapIV:     wrapIV,
		WrappedDEK: wrappedDEK,
		WrapTag:    wrapTag,
		RecordIV:   recordIV,
		RecordCT:   recordCT,
		RecordTag:  recordTag,
	}
	return encodeEnvelope(env), nil
}

// Open decrypts a persisted enc:v1 value. It refuses any malformed input and
// any authentication failure; it never returns partially-decrypted or plaintext
// data on error (ADR-SEC-01, fail-closed).
func Open(kek []byte, encoded string) ([]byte, error) {
	env, err := ParseEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	if len(kek) != KEKSize {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "kek is not 32 bytes"}),
		)
	}

	wrapAEAD, err := newGCMFn(kek)
	if err != nil {
		return nil, err
	}
	dek, err := wrapAEAD.Open(nil, env.WrapIV, append(env.WrappedDEK, env.WrapTag...), nil)
	if err != nil {
		// Wrong KEK or tampered wrap. Both are the same opaque failure to the
		// caller; distinguishing them would be an oracle.
		return nil, domain.New(domain.CodeSecretDecryptFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
		)
	}
	// Defensive invariant: ParseEnvelope pins WrappedDEK to exactly DEKSize
	// bytes and GCM ciphertext length always equals plaintext length, so this
	// guard cannot fire on any input a caller can construct. It is kept as a
	// belt-and-braces check so a future format change cannot silently accept a
	// short DEK; hence it stays uncovered by design.
	if len(dek) != DEKSize {
		return nil, domain.New(domain.CodeSecretDecryptFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "unwrapped DEK is not 32 bytes"}),
		)
	}

	recordAEAD, err := newGCMFn(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := recordAEAD.Open(nil, env.RecordIV, append(env.RecordCT, env.RecordTag...), nil)
	if err != nil {
		return nil, domain.New(domain.CodeSecretDecryptFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
		)
	}
	return plaintext, nil
}

// Rewrap re-wraps only the DEK under a new KEK, leaving the record ciphertext
// and its IV/tag byte-identical. This is what makes rotation incremental: the
// cost is proportional to the number of records, not to their size, and a
// record the new KEK has not yet touched stays readable with the old one as
// long as the caller keeps both.
func Rewrap(oldKEK, newKEK []byte, encoded string) (string, error) {
	env, err := ParseEnvelope(encoded)
	if err != nil {
		return "", err
	}
	oldAEAD, err := newGCMFn(oldKEK)
	if err != nil {
		return "", err
	}
	dek, err := oldAEAD.Open(nil, env.WrapIV, append(env.WrappedDEK, env.WrapTag...), nil)
	if err != nil {
		return "", domain.New(domain.CodeSecretDecryptFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
		)
	}

	newAEAD, err := newGCMFn(newKEK)
	if err != nil {
		return "", err
	}
	wrapIV := make([]byte, IVSize)
	if _, err := io.ReadFull(randReader, wrapIV); err != nil {
		return "", wrapRand(err)
	}
	wrapped := newAEAD.Seal(nil, wrapIV, dek, nil)
	wrappedDEK, wrapTag := splitTag(wrapped)

	rewrapped := &Envelope{
		WrapIV:     wrapIV,
		WrappedDEK: wrappedDEK,
		WrapTag:    wrapTag,
		RecordIV:   env.RecordIV,
		RecordCT:   env.RecordCT,
		RecordTag:  env.RecordTag,
	}
	return encodeEnvelope(rewrapped), nil
}

// ParseEnvelope splits and validates an enc:v1 value without touching any key.
// Strictness is the point: the prefix must be exactly enc:v1, the IV exactly 12
// bytes, the tag exactly 16, and the inner blob of a known version and minimum
// size.
func ParseEnvelope(encoded string) (*Envelope, error) {
	parts := strings.Split(encoded, ":")
	if len(parts) != 5 {
		return nil, invalidFormat("expected 5 colon-separated parts")
	}
	if parts[0] != prefix {
		return nil, invalidFormat("missing enc prefix")
	}
	if parts[1] != version {
		return nil, domain.New(domain.CodeSecretUnknownVersion,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"version": parts[1]}),
		)
	}

	wrapIV, err := b64decode(parts[2])
	if err != nil {
		return nil, err
	}
	if len(wrapIV) != IVSize {
		return nil, invalidFormat(fmt.Sprintf("iv is %d bytes, want %d", len(wrapIV), IVSize))
	}
	blob, err := b64decode(parts[3])
	if err != nil {
		return nil, err
	}
	wrapTag, err := b64decode(parts[4])
	if err != nil {
		return nil, err
	}
	if len(wrapTag) != TagSize {
		return nil, invalidFormat(fmt.Sprintf("tag is %d bytes, want %d", len(wrapTag), TagSize))
	}
	if len(blob) < blobMinSize {
		return nil, invalidFormat(fmt.Sprintf("envelope blob is %d bytes, want at least %d", len(blob), blobMinSize))
	}
	if blob[0] != blobVersion {
		return nil, domain.New(domain.CodeSecretUnknownVersion,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"version": fmt.Sprintf("blob%d", blob[0])}),
		)
	}

	env := &Envelope{WrapIV: wrapIV, WrapTag: wrapTag}
	env.WrappedDEK = clone(blob[1 : 1+DEKSize])
	env.RecordIV = clone(blob[1+DEKSize : 1+DEKSize+IVSize])
	env.RecordCT = clone(blob[1+DEKSize+IVSize : len(blob)-TagSize])
	env.RecordTag = clone(blob[len(blob)-TagSize:])
	return env, nil
}

// encodeEnvelope serialises an Envelope into the persisted form. The inner blob
// carries the DEK wrap, the record IV/ciphertext/tag; the outer iv and tag are
// the DEK-wrap's, so exactly one GCM iv/tag pair appears in each layer.
func encodeEnvelope(env *Envelope) string {
	blob := make([]byte, 0, blobMinSize+len(env.RecordCT))
	blob = append(blob, blobVersion)
	blob = append(blob, env.WrappedDEK...)
	blob = append(blob, env.RecordIV...)
	blob = append(blob, env.RecordCT...)
	blob = append(blob, env.RecordTag...)

	return prefix + ":" + version + ":" +
		b64encode(env.WrapIV) + ":" + b64encode(blob) + ":" + b64encode(env.WrapTag)
}

// newGCMFn is a seam over newGCM so the caller's error-propagation branches
// (Seal/Open/Rewrap/recovery) are reachable in tests. cipher.NewGCM cannot fail
// for a valid AES block, so the branch is otherwise dead.
var newGCMFn = newGCM

// newAESBlock is a seam over aes.NewCipher so a test can return a block whose
// BlockSize is not 16, reaching the cipher.NewGCM guard that a real AES block
// can never trigger.
var newAESBlock = aes.NewCipher

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := newAESBlock(key)
	if err != nil {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "invalid AES key"}),
		)
	}
	// cipher.NewGCM requires a 128-bit block. aes.NewCipher always satisfies it,
	// so this guard only fires if the block construction is swapped for a cipher
	// with a different block size; the newAESBlock seam makes it testable.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot build GCM"}),
		)
	}
	return aead, nil
}

// splitTag separates the trailing GCM tag from a Seal result, so the persisted
// layout stores it as its own field and its length is pinned by the parser.
func splitTag(sealed []byte) (ct, tag []byte) {
	n := len(sealed) - TagSize
	return sealed[:n], sealed[n:]
}

func b64encode(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, invalidFormat("not valid base64")
	}
	return b, nil
}

func invalidFormat(reason string) error {
	return domain.New(domain.CodeSecretInvalidFormat,
		domain.WithHTTPStatus(500),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}

func wrapRand(err error) error {
	return domain.New(domain.CodeSecretKDFFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": "cannot read random bytes"}),
	)
}

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
