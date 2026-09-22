// Package oauth implements the generic OAuth flows of F1.5: RFC 8628
// device_code and authorization_code with PKCE S256.
//
// The flows are transport-injectable: every network call goes through a
// policy-bound doer, so a test drives them against an httptest.Server. No flow
// logs a device_code, a code, an access token or a refresh token.
//
// Security invariants (ADR-003 / ADR-SEC-05 / review SEC-05, SEC-06):
//   - PKCE S256 is mandatory; a flow without a verifier is rejected.
//   - The state is at least 128 bits from crypto/rand and single-use.
//   - The callback listener binds 127.0.0.1 on an EPHEMERAL port.
//   - The redirect URI must be on the descriptor allowlist by EXACT match.
//   - EVERY outbound call goes through the ADR-SEC-05 EgressPolicy: TLS
//     verified, SSRF dial-time denylist, and redirects refused. A flow with no
//     policy and no test client fails CLOSED rather than using
//     http.DefaultClient (which would follow a 30x and leak the Bearer token).
//   - A token endpoint error is mapped onto the ADR-0002 taxonomy with typed
//     Scope/Retryable, never inferred from the string.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// maxResponseBytes bounds a token endpoint response.
const maxResponseBytes = 1 << 20 // 1 MiB

// ClientDeps are the injectable dependencies of a flow.
type ClientDeps struct {
	// Egress is the mandatory ADR-SEC-05 outbound-transport policy. EVERY OAuth
	// network call (token exchange, device polling, userinfo, loadCodeAssist,
	// onboardUser, refresh) builds its client from it, so TLS verification, the
	// SSRF dial-time denylist and redirect blocking apply to OAuth exactly as to
	// inference. It is the production path.
	Egress contracts.EgressPolicy
	// HTTP is a pre-built, policy-bound client for tests. When set it WINS over
	// Egress. It exists so a test can point the flow at an httptest.Server
	// without a real policy; it is never set in production. A nil HTTP with a
	// nil Egress is a wiring error and fails closed (see doerFor) rather than
	// falling back to http.DefaultClient, which follows redirects and would
	// leak the Authorization header (ADR-SEC-05 §4).
	HTTP contracts.HTTPDoer
	// AllowLoopback unlocks the loopback exception when Egress builds the client
	// for an explicit loopback literal (a local test/Mock server). Production
	// leaves it false: every real OAuth endpoint is HTTPS.
	AllowLoopback bool
	// Clock is the injectable time source.
	Clock contracts.Clock
	// DeviceKeyGenerator is reserved for device_code identity; unused in v1.
	// Kept as a documented seam so the constructor signature stays stable.
	Now func() time.Time
}

// defaultResponseHeaderTimeout bounds TTFT for an OAuth endpoint.
const defaultResponseHeaderTimeout = 30 * time.Second

// doerFor returns the HTTP doer for one endpoint.
//
//   - A pre-built HTTP (tests) wins, unchanged.
//   - Otherwise the ADR-SEC-05 EgressPolicy builds a policy-bound client for
//     this exact endpoint: TLS verified, SSRF dial-time denylist enforced, and
//     CheckRedirect refusing every 30x (http.ErrUseLastResponse), so a hostile
//     token/userinfo endpoint cannot bounce the Bearer token to another host.
//   - With neither configured it fails CLOSED with a typed error. It never
//     returns http.DefaultClient: that client follows redirects, which is the
//     exact ADR-SEC-05 §4 bypass this guards against.
func (d ClientDeps) doerFor(endpoint string) (contracts.HTTPDoer, error) {
	if d.HTTP != nil {
		return d.HTTP, nil
	}
	if d.Egress == nil {
		return nil, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithParams(map[string]string{"reason": "no egress policy configured for OAuth"}),
		)
	}
	return d.Egress.Client(contracts.EgressSpec{
		BaseURL:               endpoint,
		AllowLoopback:         d.AllowLoopback,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		// Redirects are refused by the policy; MaxRedirects must stay zero when
		// FollowRedirects is false, or the spec is invalid.
		FollowRedirects: false,
	})
}

func (d ClientDeps) now() time.Time {
	if d.Clock != nil {
		return d.Clock.Now()
	}
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// tokenResponse is the shared JSON shape of an OAuth token endpoint.
//
// Field names differ per provider (RFC 6749 uses snake_case, some providers
// add camelCase aliases), so the struct accepts both spellings and the flow
// normalises. Unknown fields are ignored.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`

	// Provider-specific camelCase aliases seen in the wild.
	AccessTokenCamel  string `json:"accessToken"`
	RefreshTokenCamel string `json:"refreshToken"`
	ExpiresInCamel    int64  `json:"expiresIn"`
}

func (t tokenResponse) access() string {
	if t.AccessToken != "" {
		return t.AccessToken
	}
	return t.AccessTokenCamel
}

func (t tokenResponse) refresh() string {
	if t.RefreshToken != "" {
		return t.RefreshToken
	}
	return t.RefreshTokenCamel
}

func (t tokenResponse) expiresIn() int64 {
	if t.ExpiresIn != 0 {
		return t.ExpiresIn
	}
	return t.ExpiresInCamel
}

// errorResponse is the OAuth error shape (RFC 6749 §5.2, RFC 8628 §3.5).
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// postForm performs a form POST and decodes either a token or an OAuth error.
// A non-2xx status is still parsed when it carries an OAuth error body, because
// providers return 400/401 with a meaningful `error`.
func (d ClientDeps) postForm(ctx context.Context, endpoint string, form url.Values) (tokenResponse, error) {
	doer, err := d.doerFor(endpoint)
	if err != nil {
		return tokenResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, flowError(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return tokenResponse{}, networkError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return tokenResponse{}, networkError(err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var oe errorResponse
		if json.Unmarshal(body, &oe) == nil && oe.Error != "" {
			return tokenResponse{}, mapOAuthError(oe.Error, oe.ErrorDescription)
		}
		return tokenResponse{}, networkError(fmt.Errorf("token endpoint returned %d", resp.StatusCode))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return tokenResponse{}, flowError(fmt.Errorf("token endpoint returned invalid JSON"))
	}
	return tr, nil
}

// resultFromToken builds the AuthResult the caller seals. The refresh token is
// marked Rotated only when the response carried one, so a provider that reuses
// the previous refresh token does not lose it.
func resultFromToken(d ClientDeps, tr tokenResponse, mode contracts.AuthMode, previous contracts.RefreshToken) contracts.AuthResult {
	access := tr.access()
	res := contracts.AuthResult{
		Access:   contracts.Secret(access),
		AuthMode: mode,
	}
	if tr.expiresIn() > 0 {
		res.ExpiresAt = d.now().Add(time.Duration(tr.expiresIn()) * time.Second)
	}

	refresh := tr.refresh()
	switch {
	case refresh != "":
		res.Token = contracts.RefreshToken{Token: contracts.Secret(refresh), Rotated: true}
	case !previous.Token.IsEmpty():
		// No new refresh token: keep the previous one (RFC 6749 §6).
		res.Token = previous
	}

	if tr.Scope != "" {
		res.Scopes = strings.Fields(tr.Scope)
	}
	return res
}

// --- error mapping (ADR-0002 taxonomy) ---

// mapOAuthError turns a provider error code into a typed DomainError.
func mapOAuthError(code, description string) error {
	switch code {
	case "authorization_pending":
		// Not terminal: the caller keeps polling. Surfaced as a sentinel the
		// device flow recognises, never as a user-facing failure.
		return errAuthorizationPending
	case "slow_down":
		return errSlowDown
	case "access_denied":
		return domain.New(domain.CodeAuthOAuthDenied,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
		)
	case "expired_token":
		return domain.New(domain.CodeAuthFlowExpired,
			domain.WithHTTPStatus(408),
			domain.WithScope(domain.ScopeRequest),
		)
	case "invalid_grant":
		// A rejected/revoked refresh token: not retryable, invalidate.
		return domain.New(domain.CodeAuthCredentialInvalid,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
		)
	case "invalid_client", "unauthorized_client":
		return domain.New(domain.CodeAuthCredentialInvalid,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
		)
	case "insufficient_scope":
		return domain.New(domain.CodeAuthScopeInsufficient,
			domain.WithHTTPStatus(403),
			domain.WithScope(domain.ScopeCredential),
		)
	default:
		_ = description // never echoed: it can contain provider internals
		return domain.New(domain.CodeAuthRefreshFailed,
			domain.WithHTTPStatus(502),
			domain.Retry(),
			domain.WithScope(domain.ScopeCredential),
		)
	}
}

// networkError classifies a transport failure as a retryable provider error.
//
// A typed egress-policy refusal (the SSRF dial-time denial or the scheme rule)
// wrapped by net/http in *url.Error is preserved VERBATIM instead of being
// folded into auth.refresh_failed: those are fail-closed security outcomes
// (ADR-SEC-05 §8) and must not look like a transient credential failure.
func networkError(err error) error {
	if de := egressPolicyError(err); de != nil {
		return de
	}
	return domain.New(domain.CodeAuthRefreshFailed,
		domain.WithHTTPStatus(502),
		domain.Retry(),
		domain.WithScope(domain.ScopeCredential),
		domain.WithCause(err),
	)
}

// egressPolicyError extracts a typed egress-policy refusal from a transport
// error (net/http wraps it in *url.Error), returning nil for anything else.
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

func flowError(err error) error {
	return domain.New(domain.CodeAuthRefreshFailed,
		domain.WithHTTPStatus(502),
		domain.WithCause(err),
	)
}

// --- PKCE + state helpers ---

// randReader is the entropy source for the state and PKCE verifier. It is a
// package variable so a test can inject a failing reader and cover the
// crypto/rand error branch. Production never changes it.
var randReader io.Reader = rand.Reader

// NewState returns a single-use anti-CSRF state of at least 128 bits.
func NewState() (string, error) {
	buf := make([]byte, 32) // 256 bits, comfortably above the 128-bit floor
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", flowError(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewPKCEVerifier returns a code verifier and its S256 challenge (RFC 7636).
// The verifier is 43 chars of base64url, the minimum the spec allows.
func NewPKCEVerifier() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", "", flowError(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// errAuthorizationPending and errSlowDown are internal sentinels used by the
// device flow's polling loop. They never escape Poll.
var (
	errAuthorizationPending = fmt.Errorf("authorization pending")
	errSlowDown             = fmt.Errorf("slow down")
)

// jsonMarshal is a seam over json.Marshal for the best-effort Antigravity
// discovery payloads. Those values (a small metadata struct) cannot actually
// fail to marshal, so the error branch is only reachable through the seam; a
// test injects a failure to prove the flow degrades gracefully instead of
// panicking.
var jsonMarshal = json.Marshal
