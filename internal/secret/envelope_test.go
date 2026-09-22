package secret

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// testParams are cheap so the suite does not spend a second per derivation.
var testParams = KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32}

func testKEK(t *testing.T) []byte {
	t.Helper()
	kek, err := DeriveKEK([]byte("test-passphrase"), bytes.Repeat([]byte{0x11}, SaltSize), testParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	return kek
}

func TestSealOpenRoundTrip(t *testing.T) {
	kek := testKEK(t)

	values := [][]byte{
		[]byte("sk-live-supersecret"),
		[]byte(""),
		{0x00, 0x01, 0xff, 0xfe, 0x80},
		bytes.Repeat([]byte("A"), 10_000),
	}
	for _, plaintext := range values {
		encoded, err := Seal(kek, plaintext)
		if err != nil {
			t.Fatalf("Seal(%q): %v", plaintext, err)
		}
		if !strings.HasPrefix(encoded, "enc:v1:") {
			t.Fatalf("encoded %q does not carry the versioned prefix", encoded)
		}
		got, err := Open(kek, encoded)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-trip mismatch: got %q want %q", got, plaintext)
		}
	}
}

// TestSealUsesFreshIV proves the IV is per-operation: two seals of the same
// plaintext must differ, otherwise the keystream would repeat.
func TestSealUsesFreshIV(t *testing.T) {
	kek := testKEK(t)
	a, _ := Seal(kek, []byte("same"))
	b, _ := Seal(kek, []byte("same"))
	if a == b {
		t.Fatal("two seals of the same plaintext are identical; IV is not fresh")
	}
}

func TestParseEnvelopeStrictness(t *testing.T) {
	kek := testKEK(t)
	valid, err := Seal(kek, []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	parts := strings.Split(valid, ":")

	tests := []struct {
		name    string
		mutate  func([]string) string
		wantErr string
	}{
		{
			name:    "unknown prefix",
			mutate:  func(p []string) string { return strings.Replace(valid, "enc:v1:", "plain:v1:", 1) },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "missing version",
			mutate:  func(p []string) string { return strings.Replace(valid, "enc:v1:", "enc:", 1) },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "unknown version",
			mutate:  func(p []string) string { return strings.Replace(valid, "enc:v1:", "enc:v2:", 1) },
			wantErr: domain.CodeSecretUnknownVersion,
		},
		{
			name:    "iv too short",
			mutate:  func(p []string) string { p[2] = b64encode(bytes.Repeat([]byte{1}, 8)); return strings.Join(p, ":") },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "iv too long",
			mutate:  func(p []string) string { p[2] = b64encode(bytes.Repeat([]byte{1}, 16)); return strings.Join(p, ":") },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "tag too short",
			mutate:  func(p []string) string { p[4] = b64encode(bytes.Repeat([]byte{1}, 8)); return strings.Join(p, ":") },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "not base64",
			mutate:  func(p []string) string { p[2] = "!!!!"; return strings.Join(p, ":") },
			wantErr: domain.CodeSecretInvalidFormat,
		},
		{
			name:    "too few parts",
			mutate:  func(p []string) string { return strings.Join(p[:3], ":") },
			wantErr: domain.CodeSecretInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := tt.mutate(append([]string(nil), parts...))
			_, err := Open(kek, mutated)
			if err == nil {
				t.Fatalf("Open accepted malformed input %q", mutated)
			}
			de, ok := err.(*domain.DomainError)
			if !ok || de.Code != tt.wantErr {
				t.Fatalf("err = %v, want code %s", err, tt.wantErr)
			}
		})
	}
}

// TestOpenRejectsTruncatedTag is acceptance criterion 2: a truncated tag must
// fail authentication, never yield plaintext.
func TestOpenRejectsTruncatedTag(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("secret-value"))
	parts := strings.Split(encoded, ":")

	fullTag, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}
	// Truncate the tag inside the alphabet so it is still valid base64 but the
	// wrong length: the parser must catch the length, not just the auth failure.
	parts[4] = b64encode(fullTag[:TagSize-1])
	if _, err := Open(kek, strings.Join(parts, ":")); err == nil {
		t.Fatal("truncated tag accepted")
	}

	// And a bit-flip in a full-length tag must fail authentication.
	flipped := append([]byte(nil), fullTag...)
	flipped[0] ^= 0xff
	parts[4] = b64encode(flipped)
	if _, err := Open(kek, strings.Join(parts, ":")); err == nil {
		t.Fatal("corrupted tag accepted")
	}
}

func TestOpenWithWrongKEKFails(t *testing.T) {
	kekA := testKEK(t)
	kekB, _ := DeriveKEK([]byte("other-passphrase"), bytes.Repeat([]byte{0x22}, SaltSize), testParams)

	encoded, _ := Seal(kekA, []byte("secret"))
	got, err := Open(kekB, encoded)
	if err == nil {
		t.Fatalf("wrong KEK decrypted the blob: %q", got)
	}
	if got != nil {
		t.Fatal("failure must return nil plaintext, never partial data")
	}
}

// TestRewrapPreservesRecord is acceptance criterion 5: rotation changes only the
// DEK wrap, so the record remains readable and the ciphertext is untouched.
func TestRewrapPreservesRecord(t *testing.T) {
	oldKEK := testKEK(t)
	newKEK, _ := DeriveKEK([]byte("new-passphrase"), bytes.Repeat([]byte{0x33}, SaltSize), testParams)

	encoded, _ := Seal(oldKEK, []byte("rotate-me"))
	before, err := ParseEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}

	rotated, err := Rewrap(oldKEK, newKEK, encoded)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	after, err := ParseEnvelope(rotated)
	if err != nil {
		t.Fatalf("ParseEnvelope(rotated): %v", err)
	}

	// The record ciphertext/IV/tag must be byte-identical: only the DEK wrap and
	// its IV/tag may change.
	if !bytes.Equal(before.RecordCT, after.RecordCT) ||
		!bytes.Equal(before.RecordIV, after.RecordIV) ||
		!bytes.Equal(before.RecordTag, after.RecordTag) {
		t.Error("rotation rewrote the record ciphertext instead of only the DEK wrap")
	}
	if bytes.Equal(before.WrappedDEK, after.WrappedDEK) {
		t.Error("rotation did not re-wrap the DEK")
	}

	// Readable under the new KEK, unreadable under the old one.
	plain, err := Open(newKEK, rotated)
	if err != nil || string(plain) != "rotate-me" {
		t.Fatalf("Open under new KEK: %q, %v", plain, err)
	}
	if _, err := Open(oldKEK, rotated); err == nil {
		t.Error("old KEK still decrypts a rotated record")
	}

	// The original record is still readable under the old KEK (incremental
	// migration: both versions coexist).
	if plain, err := Open(oldKEK, encoded); err != nil || string(plain) != "rotate-me" {
		t.Fatalf("original record unreadable during migration: %q, %v", plain, err)
	}
}

func TestSealRejectsBadKEKLength(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x")); err == nil {
		t.Fatal("Seal accepted a non-32-byte KEK")
	}
}
