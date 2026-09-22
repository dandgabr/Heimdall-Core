package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// partialReader returns n bytes on the first call, then fails. It lets a test
// drive the SECOND/THIRD entropy read (record IV, wrap IV) without failing the
// first, which a wholly-failing reader cannot.
type partialReader struct {
	remaining int
}

func (p *partialReader) Read(b []byte) (int, error) {
	if p.remaining <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	n := len(b)
	if n > p.remaining {
		n = p.remaining
	}
	for i := 0; i < n; i++ {
		b[i] = 0x5a
	}
	p.remaining -= n
	return n, nil
}

// TestSealFailsOnSecondEntropyRead covers the record-IV read failure: the DEK
// read succeeds, then the reader fails.
func TestSealFailsOnSecondEntropyRead(t *testing.T) {
	kek := testKEK(t)
	old := randReader
	randReader = &partialReader{remaining: DEKSize}
	t.Cleanup(func() { randReader = old })
	if _, err := Seal(kek, []byte("x")); err == nil {
		t.Fatal("Seal succeeded when the record IV read failed")
	}
	randReader = old
}

// TestSealFailsOnThirdEntropyRead covers the wrap-IV read failure: DEK and
// record IV succeed, then the reader fails.
func TestSealFailsOnThirdEntropyRead(t *testing.T) {
	kek := testKEK(t)
	old := randReader
	randReader = &partialReader{remaining: DEKSize + IVSize}
	t.Cleanup(func() { randReader = old })
	if _, err := Seal(kek, []byte("x")); err == nil {
		t.Fatal("Seal succeeded when the wrap IV read failed")
	}
	randReader = old
}

// TestOpenRejectsBadKEKLength covers Open's KEK-length check with a VALID
// envelope, so ParseEnvelope succeeds and the length check is reached.
func TestOpenRejectsBadKEKLength(t *testing.T) {
	kek := testKEK(t)
	encoded, err := Seal(kek, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Open([]byte("short"), encoded)
	if err == nil {
		t.Fatal("Open accepted a short KEK with a valid envelope")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretKDFFailed {
		t.Fatalf("err = %v, want secret.kdf_failed", err)
	}
}

// TestOpenRejectsTamperedWrappedDEK covers Open's DEK-unwrap authentication
// failure: a bit-flip in the wrapped DEK must fail, never yield plaintext.
func TestOpenRejectsTamperedWrappedDEK(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("secret"))
	env, err := ParseEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	// Corrupt the wrapped DEK, then re-encode.
	env.WrappedDEK[0] ^= 0xff
	tampered := encodeEnvelope(env)
	if _, err := Open(kek, tampered); err == nil {
		t.Fatal("tampered wrapped DEK accepted")
	}
}

// TestOpenRejectsTamperedRecord covers Open's record-decrypt authentication
// failure.
func TestOpenRejectsTamperedRecord(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("secret"))
	env, _ := ParseEnvelope(encoded)
	env.RecordCT[0] ^= 0xff
	if _, err := Open(kek, encodeEnvelope(env)); err == nil {
		t.Fatal("tampered record accepted")
	}
}

// TestRewrapRejectsBadKEKLengths covers Rewrap's error branches for a short
// old/new KEK.
func TestRewrapRejectsBadKEKLengths(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("x"))

	// Old KEK the wrong length: newGCM fails inside Rewrap.
	if _, err := Rewrap([]byte("short"), kek, encoded); err == nil {
		t.Error("Rewrap accepted a short old KEK")
	}
	// New KEK the wrong length.
	if _, err := Rewrap(kek, []byte("short"), encoded); err == nil {
		t.Error("Rewrap accepted a short new KEK")
	}
}

// TestRewrapRejectsMalformedBlob covers Rewrap's ParseEnvelope failure.
func TestRewrapRejectsMalformedBlob(t *testing.T) {
	kek := testKEK(t)
	if _, err := Rewrap(kek, kek, "not-an-envelope"); err == nil {
		t.Fatal("Rewrap accepted a malformed blob")
	}
}

// TestRewrapRejectsWrongOldKEK covers Rewrap's DEK-unwrap failure with a
// well-formed blob under a different key.
func TestRewrapRejectsWrongOldKEK(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("x"))
	other, _ := DeriveKEK([]byte("other"), bytes.Repeat([]byte{9}, SaltSize), testParams)
	if _, err := Rewrap(other, kek, encoded); err == nil {
		t.Fatal("Rewrap accepted the wrong old KEK")
	}
}

// TestParseEnvelopeEveryRejection covers the parser's remaining rejection
// branches: wrong part count, unknown version, bad base64, wrong IV/tag sizes.
func TestParseEnvelopeEveryRejection(t *testing.T) {
	kek := testKEK(t)
	valid, _ := Seal(kek, []byte("x"))
	parts := splitColon(valid)

	// Wrong number of parts.
	if _, err := ParseEnvelope("enc:v1:only:three"); err == nil {
		t.Error("wrong part count accepted")
	}
	// Wrong prefix.
	if _, err := ParseEnvelope("nope:v1:" + parts[2] + ":" + parts[3] + ":" + parts[4]); err == nil {
		t.Error("wrong prefix accepted")
	}
	// Unknown version.
	if _, err := ParseEnvelope("enc:v2:" + parts[2] + ":" + parts[3] + ":" + parts[4]); err == nil {
		t.Error("unknown version accepted")
	}
	// Bad base64 in the IV.
	if _, err := ParseEnvelope("enc:v1:!!!!:" + parts[3] + ":" + parts[4]); err == nil {
		t.Error("bad base64 IV accepted")
	}
	// Wrong IV length.
	shortIV := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 4))
	if _, err := ParseEnvelope("enc:v1:" + shortIV + ":" + parts[3] + ":" + parts[4]); err == nil {
		t.Error("short IV accepted")
	}
	// Wrong tag length.
	shortTag := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 4))
	if _, err := ParseEnvelope("enc:v1:" + parts[2] + ":" + parts[3] + ":" + shortTag); err == nil {
		t.Error("short tag accepted")
	}
	// Blob too short.
	tiny := base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := ParseEnvelope("enc:v1:" + parts[2] + ":" + tiny + ":" + parts[4]); err == nil {
		t.Error("short blob accepted")
	}
}

// TestParseEnvelopeBadBase64BlobAndTag covers the base64 rejections for the
// blob (part 3) and the tag (part 4), which are separate decode sites.
func TestParseEnvelopeBadBase64BlobAndTag(t *testing.T) {
	kek := testKEK(t)
	valid, _ := Seal(kek, []byte("x"))
	parts := splitColon(valid)

	// Bad base64 in the blob.
	if _, err := ParseEnvelope("enc:v1:" + parts[2] + ":!!!!:" + parts[4]); err == nil {
		t.Error("bad-base64 blob accepted")
	}
	// Bad base64 in the tag.
	if _, err := ParseEnvelope("enc:v1:" + parts[2] + ":" + parts[3] + ":!!!!"); err == nil {
		t.Error("bad-base64 tag accepted")
	}
}

// TestParseEnvelopeBadBlobVersion covers the inner-blob version rejection: the
// outer part is valid (enc:v1, 12-byte IV, 16-byte tag) but the inner blob's
// first byte is not 0x01.
func TestParseEnvelopeBadBlobVersion(t *testing.T) {
	kek := testKEK(t)
	valid, _ := Seal(kek, []byte("x"))
	parts := splitColon(valid)

	blob, err := b64decode(parts[3])
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	blob[0] = 0x99 // corrupt the inner version byte
	bad := "enc:v1:" + parts[2] + ":" + b64encode(blob) + ":" + parts[4]

	_, err = ParseEnvelope(bad)
	if err == nil {
		t.Fatal("unknown blob version accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretUnknownVersion {
		t.Fatalf("err = %v, want secret.unknown_version", err)
	}
}

// TestUnwrapRecoveryBadCiphertextBase64 covers the ciphertext-decode rejection.
func TestUnwrapRecoveryBadCiphertextBase64(t *testing.T) {
	blob := "enc:recovery:" + b64encode(bytes.Repeat([]byte{1}, SaltSize)) + ":" +
		b64encode(bytes.Repeat([]byte{2}, IVSize)) + ":" +
		"!!!!" + ":" + b64encode(bytes.Repeat([]byte{3}, TagSize))
	if _, err := UnwrapKEKFromRecovery(blob, []byte("p"), testParams); err == nil {
		t.Fatal("bad-base64 ciphertext accepted")
	}
}

// TestRecoveredKeyWrongLength covers the "recovered key is not 32 bytes"
// branch. It is reached by wrapping a NON-32-byte value while masquerading as a
// recovery blob; the unwrap succeeds cryptographically but the length check
// rejects it.
func TestRecoveredKeyWrongLength(t *testing.T) {
	// Build a valid recovery blob manually wrapping a 16-byte "KEK".
	salt, _ := NewSalt()
	pass := []byte("pass")
	wrapKey, _ := DeriveKEK(pass, salt, testParams)
	aead, _ := newGCM(wrapKey)
	iv := bytes.Repeat([]byte{9}, IVSize)
	sealed := aead.Seal(nil, iv, bytes.Repeat([]byte{7}, 16), nil) // 16-byte payload
	ct, tag := splitTag(sealed)
	blob := "enc:recovery:" + b64encode(salt) + ":" + b64encode(iv) + ":" +
		b64encode(ct) + ":" + b64encode(tag)

	_, err := UnwrapKEKFromRecovery(blob, pass, testParams)
	if err == nil {
		t.Fatal("a 16-byte recovered key was accepted")
	}
}

// splitColon splits an encoded envelope into its parts.
func splitColon(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
