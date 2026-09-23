package contracts

import (
	"errors"
	"testing"
)

// TestCredentialBlobRoundTrip proves encode/parse is lossless for the full
// document and for an access-only grant.
func TestCredentialBlobRoundTrip(t *testing.T) {
	full := CredentialBlob{AccessToken: "at", RefreshToken: "rt"}
	raw, err := EncodeCredentialBlob(full)
	if err != nil {
		t.Fatalf("EncodeCredentialBlob: %v", err)
	}
	back, err := ParseCredentialBlob(raw)
	if err != nil {
		t.Fatalf("ParseCredentialBlob: %v", err)
	}
	if back != full {
		t.Fatalf("round trip = %+v, want %+v", back, full)
	}

	accessOnly := CredentialBlob{AccessToken: "at"}
	raw, err = EncodeCredentialBlob(accessOnly)
	if err != nil {
		t.Fatalf("EncodeCredentialBlob: %v", err)
	}
	back, err = ParseCredentialBlob(raw)
	if err != nil {
		t.Fatalf("ParseCredentialBlob: %v", err)
	}
	if back != accessOnly {
		t.Fatalf("round trip = %+v, want %+v", back, accessOnly)
	}
}

// TestParseCredentialBlobRefuses proves the strict parser: a shapeless
// document and a token-less document both fail closed.
func TestParseCredentialBlobRefuses(t *testing.T) {
	for name, raw := range map[string][]byte{
		"not json":       []byte("this is not json"),
		"empty document": []byte(`{}`),
		"wrong shape":    []byte(`{"token":"at"}`),
	} {
		if _, err := ParseCredentialBlob(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestEncodeCredentialBlobError covers the marshal-error branch through the
// package seam (a plain-string document cannot fail in production).
func TestEncodeCredentialBlobError(t *testing.T) {
	original := marshalBlob
	marshalBlob = func(CredentialBlob) ([]byte, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { marshalBlob = original })

	if _, err := EncodeCredentialBlob(CredentialBlob{AccessToken: "at"}); err == nil {
		t.Fatal("the injected marshal failure was swallowed")
	}
}
