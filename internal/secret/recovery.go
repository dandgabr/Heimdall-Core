package secret

import (
	"io"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Recovery wraps the KEK under a passphrase so losing the primary custody layer
// (TPM reset, board replacement) does not lose the vault (ADR-SEC-01 §5).
//
// The recovery blob is stored alongside the vault and contains:
//
//	enc:recovery:<salt>:<iv>:<ct>:<tag>
//
// where the passphrase is run through the same Argon2id KDF with its own
// salt, and the resulting key wraps the KEK with AES-256-GCM. Keeping a separate
// salt from the installation salt means the recovery passphrase and the primary
// layer never derive the same key even if the operator reuses the text.
const recoveryPrefix = "enc:recovery"

// RecoveryBlob is the persisted, passphrase-wrapped KEK.
type RecoveryBlob struct {
	// Salt is the KDF salt for the recovery passphrase.
	Salt []byte
	// IV is the GCM nonce.
	IV []byte
	// Ciphertext is the wrapped KEK.
	Ciphertext []byte
	// Tag authenticates the wrap.
	Tag []byte
}

// WrapKEKForRecovery encrypts kek under passphrase, returning the persisted
// string. It refuses an empty passphrase and any KEK that is not 32 bytes.
func WrapKEKForRecovery(kek []byte, passphrase []byte, params KDFParams) (string, error) {
	if len(kek) != KEKSize {
		return "", domain.New(domain.CodeSecretRecoveryFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "kek is not 32 bytes"}),
		)
	}
	if len(passphrase) == 0 {
		return "", domain.New(domain.CodeSecretRecoveryFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "recovery passphrase is empty"}),
		)
	}
	salt, err := NewSalt()
	if err != nil {
		return "", err
	}
	wrapKey, err := DeriveKEK(passphrase, salt, params)
	if err != nil {
		return "", err
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(randReader, iv); err != nil {
		return "", wrapRand(err)
	}
	aead, err := newGCMFn(wrapKey)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, iv, kek, nil)
	ct, tag := splitTag(sealed)

	return recoveryPrefix + ":" + b64encode(salt) + ":" + b64encode(iv) + ":" +
		b64encode(ct) + ":" + b64encode(tag), nil
}

// UnwrapKEKFromRecovery recovers the KEK from a recovery blob using the
// passphrase. A wrong passphrase is indistinguishable from a tampered blob:
// both fail authentication and both return secret.recovery_failed, with no
// partial output.
func UnwrapKEKFromRecovery(blob string, passphrase []byte, params KDFParams) ([]byte, error) {
	parts := splitRecovery(blob)
	if parts == nil {
		return nil, recoveryError("malformed recovery blob")
	}
	salt, err := b64decode(parts[0])
	if err != nil || len(salt) != SaltSize {
		return nil, recoveryError("bad recovery salt")
	}
	iv, err := b64decode(parts[1])
	if err != nil || len(iv) != IVSize {
		return nil, recoveryError("bad recovery iv")
	}
	ct, err := b64decode(parts[2])
	if err != nil {
		return nil, recoveryError("bad recovery ciphertext")
	}
	tag, err := b64decode(parts[3])
	if err != nil || len(tag) != TagSize {
		return nil, recoveryError("bad recovery tag")
	}
	if len(passphrase) == 0 {
		return nil, recoveryError("empty recovery passphrase")
	}

	wrapKey, err := DeriveKEK(passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	aead, err := newGCMFn(wrapKey)
	if err != nil {
		return nil, err
	}
	kek, err := aead.Open(nil, iv, append(ct, tag...), nil)
	if err != nil {
		return nil, recoveryError("passphrase did not authenticate")
	}
	if len(kek) != KEKSize {
		return nil, recoveryError("recovered key is not 32 bytes")
	}
	return kek, nil
}

// splitRecovery splits the fixed shape and validates the prefix, returning nil
// on any deviation. It deliberately does NOT validate the body parts' base64:
// each part is decoded at its own site in UnwrapKEKFromRecovery, so the decoder
// errors stay independently reachable and reported with a specific reason.
func splitRecovery(blob string) []string {
	// enc : recovery : salt : iv : ct : tag
	const expected = 6
	parts := make([]string, 0, expected)
	start := 0
	for i := 0; i <= len(blob); i++ {
		if i == len(blob) || blob[i] == ':' {
			parts = append(parts, blob[start:i])
			start = i + 1
		}
	}
	if len(parts) != expected {
		return nil
	}
	if parts[0] != "enc" || parts[1] != "recovery" {
		return nil
	}
	return parts[2:]
}

func recoveryError(reason string) error {
	return domain.New(domain.CodeSecretRecoveryFailed,
		domain.WithHTTPStatus(500),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}
