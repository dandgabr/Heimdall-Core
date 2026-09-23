package cloudcode

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// jsonRaw is an alias kept local so requestid.go does not import encoding/json
// under an ambiguous name.
type jsonRaw = json.RawMessage

// jsonUnmarshal is a thin indirection so helpers do not repeat the json import.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// jsonMarshal is a seam over json.Marshal. The values this package marshals
// (maps of json.RawMessage decoded from valid JSON, small structs) cannot
// actually fail to marshal, so the error branches would be unreachable without
// the seam; routing every error-checked marshal through it lets a test inject a
// failure and prove the error path returns a typed error, matching the pattern
// the store and obfuscate packages use.
var jsonMarshal = json.Marshal

// errIdleTimeout marks an SSE idle expiry (mirrors the OpenAI-compatible
// executor): a plain sentinel classified explicitly by transportError.
var errIdleTimeout = errors.New("cloudcode: sse stream idle timeout")

// openCredential resolves the credential's secret. AuthNone returns empty;
// AuthAPIKey opens the sealed blob as the raw key; AuthOAuth opens a
// contracts.CredentialBlob JSON document and yields its access token (the
// refresh token stays inside the ciphertext, never crosses this boundary).
// Secrets and a non-empty sealed blob are required for both; every failure is
// fail-closed.
func openCredential(deps contracts.ExecutorDeps, cred contracts.Credential) (string, error) {
	switch cred.AuthMode {
	case contracts.AuthNone:
		return "", nil
	case contracts.AuthAPIKey, contracts.AuthOAuth:
		if deps.Secrets == nil || len(cred.Sealed) == 0 {
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
			)
		}
		plaintext, err := deps.Secrets.Open(string(cred.Sealed))
		if err != nil {
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
			)
		}
		if cred.AuthMode == contracts.AuthAPIKey {
			return string(plaintext), nil
		}
		blob, err := contracts.ParseCredentialBlob(plaintext)
		if err != nil {
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
				domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "the stored oauth credential is malformed; log in again"}),
			)
		}
		return blob.AccessToken, nil
	default:
		// A stored credential with an unknown mode: credential.invalid_auth_mode
		// is the right code, but its message expects {id, mode}.
		return "", domain.New(domain.CodeCredentialInvalidAuthMode,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"id": string(cred.ID), "mode": cred.AuthMode.String()}),
		)
	}
}

// transportError maps a transport failure to a DomainError (ADR-0002). A typed
// egress-policy denial (SSRF) is preserved verbatim, never folded into a
// retryable upstream_unavailable.
func transportError(err error) *domain.DomainError {
	if err == nil {
		return nil
	}
	if de := egressPolicyError(err); de != nil {
		return de
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.New(domain.CodeUpstreamTimeout,
			domain.WithHTTPStatus(http.StatusGatewayTimeout),
			domain.WithScope(domain.ScopeProvider),
			domain.WithCause(err),
		)
	}
	if errors.Is(err, errIdleTimeout) || isTimeout(err) {
		return domain.New(domain.CodeUpstreamTimeout,
			domain.WithHTTPStatus(http.StatusGatewayTimeout),
			domain.Retry(),
			domain.WithScope(domain.ScopeProvider),
			domain.WithCause(err),
		)
	}
	return domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.Retry(),
		domain.WithScope(domain.ScopeProvider),
		domain.WithCause(err),
	)
}

// egressPolicyError extracts a typed egress-policy refusal from an arbitrary
// transport error (net/http wraps it in *url.Error).
func egressPolicyError(err error) *domain.DomainError {
	var de *domain.DomainError
	if !errors.As(err, &de) {
		return nil
	}
	switch de.Code {
	case domain.CodeUpstreamDestinationDenied, domain.CodeUpstreamInsecureURL:
		return de
	default:
		return nil
	}
}

// isTimeout reports whether err is a net timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// max returns the larger of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
