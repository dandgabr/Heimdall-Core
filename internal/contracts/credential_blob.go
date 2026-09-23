package contracts

import (
	"encoding/json"
	"fmt"
)

// CredentialBlob is the plaintext document sealed inside an OAuth credential
// (ADR-SEC-01 custody; BD-02 login). An OAuth account carries TWO secret
// values — the access token the Executor presents as the Bearer credential and
// the refresh token that renews it — so the sealed envelope holds both, and
// the refresh token never lives anywhere unencrypted: not in the vault, not in
// Meta (which is loggable by contract), not on disk.
//
// The blob is sealed with SecretStore.Seal exactly like an API key; the
// difference is only the document shape. It is the single wire format between
// the writers (the login flow and the refresh path) and the readers (the
// executors, which extract AccessToken), so the shape cannot drift per caller.
type CredentialBlob struct {
	// AccessToken is the bearer credential the executor presents upstream.
	AccessToken string `json:"access_token"`
	// RefreshToken renews the access token. Empty for a grant that returned
	// none (the provider may withhold it); Refresh then fails closed with
	// auth.credential_invalid instead of guessing.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// marshalBlob is a seam over json.Marshal for the blob encoder. The document
// is all plain strings, so the marshal cannot fail on real input; the seam
// exists only so the error branch is reachable in a test (the store's
// marshalMeta pattern).
var marshalBlob = func(b CredentialBlob) ([]byte, error) { return json.Marshal(b) }

// EncodeCredentialBlob serialises the blob for sealing. The fields are plain
// strings, so the marshal cannot fail in practice; the error return keeps the
// caller's error path typed instead of ignored.
func EncodeCredentialBlob(b CredentialBlob) ([]byte, error) {
	raw, err := marshalBlob(b)
	if err != nil {
		return nil, fmt.Errorf("encode credential blob: %w", err)
	}
	return raw, nil
}

// ParseCredentialBlob decodes a decrypted OAuth credential. It is STRICT: an
// empty or shapeless document is an error, never an empty blob, so a truncated
// or hand-written row fails closed (the caller refuses the credential) instead
// of sending an empty bearer token upstream. A missing access token with a
// present refresh token is accepted: refresh is still possible, and the
// executor's own "no secret" guard covers the use case.
func ParseCredentialBlob(plaintext []byte) (CredentialBlob, error) {
	var b CredentialBlob
	if err := json.Unmarshal(plaintext, &b); err != nil {
		return CredentialBlob{}, fmt.Errorf("credential blob is not a valid oauth document: %w", err)
	}
	if b.AccessToken == "" && b.RefreshToken == "" {
		return CredentialBlob{}, fmt.Errorf("credential blob carries no token material")
	}
	return b, nil
}
