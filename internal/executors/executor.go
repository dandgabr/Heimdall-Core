// Package executors implements the frozen contracts.Executor for provider
// families (plan v2, F2.2).
//
// An Executor is TRANSPORT + AUTH only: it opens the credential's sealed secret,
// builds the upstream HTTP request, moves bytes, and decodes the response. It
// does NOT translate schemas — that is the family Translator's job (pure, golden
// tested). The OpenAI-compatible family is the identity translator, so this
// executor forwards the canonical bytes verbatim.
//
// The executor never builds an http.Client: the client comes from
// contracts.ExecutorDeps.Egress (ADR-SEC-05). It never logs or echoes the
// credential: auth is read from the sealed blob, injected into one header, and
// scrubbed from every diagnostic.
package executors

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// AuthHeaderStyle selects how the credential is presented to the upstream.
type AuthHeaderStyle uint8

const (
	// AuthBearer sends `Authorization: Bearer <key>` (OpenAI and most compat).
	AuthBearer AuthHeaderStyle = iota
	// AuthAPIKeyHeader sends `x-api-key: <key>` (Anthropic-style).
	AuthAPIKeyHeader
)

// Limits. A router must not let an upstream exhaust memory on either side.
const (
	// DefaultMaxResponseBytes bounds a buffered (non-stream) response.
	DefaultMaxResponseBytes = 32 << 20 // 32 MiB
	// MaxErrorBodyBytes bounds how much of an upstream error body is read.
	MaxErrorBodyBytes = 8 << 10 // 8 KiB
	// maxSSEEventBytes bounds a single SSE event line, so one hostile frame
	// cannot grow memory without limit.
	maxSSEEventBytes = 1 << 20 // 1 MiB
	// DefaultResponseHeaderTimeout is the TTFT fallback when the spec leaves it
	// zero.
	DefaultResponseHeaderTimeout = 60 * time.Second
)

// Config configures an OpenAI-compatible executor. It is DATA: the family
// builds one from its descriptor.
type Config struct {
	// Family is the provider family identity.
	Family domain.ProviderID
	// BaseURL is the upstream root, e.g. https://api.openai.com/v1.
	BaseURL string
	// AllowLoopback unlocks the loopback exception for a local runtime.
	AllowLoopback bool
	// AuthStyle selects the auth header shape.
	AuthStyle AuthHeaderStyle
	// ResponseHeaderTimeout bounds TTFT.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds the gap between stream chunks.
	IdleTimeout time.Duration
	// MaxResponseBytes bounds a buffered response. Zero means the default.
	MaxResponseBytes int64
	// CountTokensEndpoint, when non-empty, is the path (relative to BaseURL) of
	// a token-counting endpoint. Empty means the family cannot count.
	CountTokensEndpoint string
}

// Executor is the concrete contracts.Executor for one family. It holds no
// account state: the credential is passed per call.
type Executor struct {
	cfg  Config
	deps contracts.ExecutorDeps
	doer contracts.HTTPDoer
}

// compile-time assertion that Executor satisfies the frozen contract.
var _ contracts.Executor = (*Executor)(nil)

// New builds the executor: it validates the deps, builds the transport through
// the egress policy (never inline), and returns a ready Executor.
func New(cfg Config, deps contracts.ExecutorDeps) (*Executor, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithParams(map[string]string{"reason": "executor: empty base url"}),
		)
	}

	headerTimeout := cfg.ResponseHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = DefaultResponseHeaderTimeout
	}
	maxResponse := cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}

	doer, err := deps.Egress.Client(contracts.EgressSpec{
		BaseURL:               cfg.BaseURL,
		AllowLoopback:         cfg.AllowLoopback,
		ResponseHeaderTimeout: headerTimeout,
		IdleTimeout:           cfg.IdleTimeout,
		MaxResponseBytes:      maxResponse,
		FollowRedirects:       false,
	})
	if err != nil {
		return nil, err
	}

	return &Executor{cfg: cfg, deps: deps, doer: doer}, nil
}

// Family implements contracts.Executor.
func (e *Executor) Family() domain.ProviderID { return e.cfg.Family }

// endpoint joins the base URL with a path, trimming the trailing slash.
func (e *Executor) endpoint(suffix string) string {
	base := strings.TrimRight(e.cfg.BaseURL, "/")
	return base + suffix
}

// openCredential resolves the credential's secret material. AuthNone has no
// secret (returns empty, no error). AuthAPIKey requires Secrets and a non-empty
// sealed blob. AuthOAuth is deferred to F3 and refused explicitly.
func (e *Executor) openCredential(cred contracts.Credential) (string, error) {
	switch cred.AuthMode {
	case contracts.AuthNone:
		return "", nil
	case contracts.AuthAPIKey:
		if e.deps.Secrets == nil {
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
			)
		}
		if len(cred.Sealed) == 0 {
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
			)
		}
		plaintext, err := e.deps.Secrets.Open(string(cred.Sealed))
		if err != nil {
			// The secret store is fail-closed; surface a credential-scoped error
			// without echoing the cause (it may name the ciphertext path).
			return "", domain.New(domain.CodeAuthSecretMissing,
				domain.WithHTTPStatus(http.StatusInternalServerError),
				domain.WithScope(domain.ScopeCredential),
			)
		}
		return string(plaintext), nil
	case contracts.AuthOAuth:
		// OAuth material is refreshed by the F3 Dispatcher before the executor is
		// called; until then an OAuth credential reaching here is a wiring error.
		return "", domain.New(domain.CodeProviderAuthModeUnsupported,
			domain.WithHTTPStatus(http.StatusNotImplemented),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"provider": string(e.cfg.Family), "mode": cred.AuthMode.String()}),
		)
	default:
		// A credential whose mode is unknown: this is the stored-credential case
		// credential.invalid_auth_mode describes, so pass its {id, mode} params.
		return "", domain.New(domain.CodeCredentialInvalidAuthMode,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"id": string(cred.ID), "mode": cred.AuthMode.String()}),
		)
	}
}

// buildRequest assembles the upstream request from the canonical WireRequest.
// The body is forwarded verbatim; extra headers from the caller are applied, and
// the auth header is set LAST so it cannot be overridden.
func (e *Executor) buildRequest(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (*http.Request, error) {
	secret, err := e.openCredential(cred)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint("/chat/completions"), bytes.NewReader(req.Body))
	if err != nil {
		return nil, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for name, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(name, v)
		}
	}
	applyAuth(httpReq, e.cfg.AuthStyle, secret)
	return httpReq, nil
}

// applyAuth sets the credential's auth header LAST, after any caller headers, so
// a caller cannot smuggle its own Authorization or override the credential. It
// clears both shapes first so only the family's chosen header is present.
func applyAuth(req *http.Request, style AuthHeaderStyle, secret string) {
	if secret == "" {
		return
	}
	req.Header.Del("Authorization")
	req.Header.Del("x-api-key")
	switch style {
	case AuthAPIKeyHeader:
		req.Header.Set("x-api-key", secret)
	default:
		req.Header.Set("Authorization", "Bearer "+secret)
	}
}

// Probe performs a minimal authenticated request to prove the credential and the
// upstream transport work end to end, WITHOUT a chat completion: it issues
// `GET {base}/models` (the OpenAI-compatible listing endpoint) with the
// credential's auth header. It returns the upstream HTTP status. A non-2xx is
// mapped through the same ADR-0002 taxonomy as a chat call, so a 401 is
// credential-scoped and non-retryable and a 5xx is provider-scoped and
// retryable. It uses the executor's EgressPolicy-bound client, so TLS, the SSRF
// denylist and redirect blocking all apply.
func (e *Executor) Probe(ctx context.Context, cred contracts.Credential) (int, error) {
	secret, err := e.openCredential(cred)
	if err != nil {
		return 0, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint("/models"), nil)
	if err != nil {
		return 0, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	httpReq.Header.Set("Accept", "application/json")
	applyAuth(httpReq, e.cfg.AuthStyle, secret)

	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return 0, transportError(err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused; the body is never
	// returned or logged.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBodyBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, e.upstreamError(resp)
	}
	return resp.StatusCode, nil
}

// Do implements contracts.Executor: one non-streaming call, buffered.
func (e *Executor) Do(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.WireResponse, error) {
	httpReq, err := e.buildRequest(ctx, req, cred)
	if err != nil {
		return contracts.WireResponse{}, err
	}
	if req.Stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}

	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return contracts.WireResponse{}, transportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return contracts.WireResponse{}, e.upstreamError(resp)
	}

	maxResponse := e.cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return contracts.WireResponse{}, transportError(err)
	}
	if int64(len(body)) > maxResponse {
		return contracts.WireResponse{}, domain.New(domain.CodeUpstreamResponseTooLarge,
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.WithScope(domain.ScopeProvider),
			domain.WithParams(map[string]string{"limit": strconv.FormatInt(maxResponse, 10)}),
		)
	}

	return contracts.WireResponse{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    body,
	}, nil
}

// CountTokens implements contracts.Executor. A family without a counting endpoint
// returns provider.executor_unavailable, never a fabricated number.
func (e *Executor) CountTokens(ctx context.Context, req contracts.WireRequest, model domain.ModelID) (int, error) {
	if e.cfg.CountTokensEndpoint == "" {
		return 0, domain.New(domain.CodeProviderNoExecutor,
			domain.WithHTTPStatus(http.StatusNotImplemented),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"provider": string(e.cfg.Family)}),
		)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint(e.cfg.CountTokensEndpoint), bytes.NewReader(req.Body))
	if err != nil {
		return 0, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return 0, transportError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, e.upstreamError(resp)
	}
	var out struct {
		Tokens int `json:"input_tokens"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	if err != nil {
		return 0, transportError(err)
	}
	if err := jsonUnmarshal(body, &out); err != nil {
		return 0, domain.New(domain.CodeBadUpstreamResponse,
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.WithScope(domain.ScopeProvider),
			domain.WithCause(err),
		)
	}
	return out.Tokens, nil
}

// transportError maps a transport failure to a DomainError (ADR-0002):
// cancellation/deadline and network/TLS are ScopeProvider retryable.
//
// A typed egress-policy denial (the SSRF dial-time control and the scheme rule)
// is preserved VERBATIM instead of being folded into the generic mapping: those
// refusals are fail-closed security outcomes (ADR-SEC-05 §8), and turning one
// into a retryable upstream_unavailable would make the F3 Dispatcher retry or
// fail over against a destination that was deliberately denied.
func transportError(err error) *domain.DomainError {
	if err == nil {
		return nil
	}
	if de := egressPolicyError(err); de != nil {
		return de
	}
	if isCanceledOrDeadline(err) {
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

// upstreamError maps an upstream non-2xx to a DomainError with the ADR-0002
// Scope/Retryable. The upstream body is drained (bounded) but never returned.
func (e *Executor) upstreamError(resp *http.Response) *domain.DomainError {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBodyBytes))

	status := resp.StatusCode
	opts := []domain.Option{domain.WithHTTPStatus(http.StatusBadGateway)}

	switch {
	case status == http.StatusTooManyRequests:
		// Rate/cota: credential-scoped, retryable, honour Retry-After.
		opts = append(opts, domain.Retry(), domain.WithScope(domain.ScopeCredential))
		if ra := parseRetryAfter(resp.Header.Get("Retry-After"), e.now()); ra > 0 {
			opts = append(opts, domain.WithRetryAfter(ra))
		}
		return domain.New(domain.CodeUpstreamUnavailable, opts...)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		// Credential rejected: not retryable, invalidates the account.
		opts = append(opts, domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}))
		return domain.New(domain.CodeUpstreamUnavailable, opts...)
	case status == http.StatusRequestTimeout || status >= 500:
		// Provider outage: provider-scoped, retryable.
		opts = append(opts, domain.Retry(),
			domain.WithScope(domain.ScopeProvider),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}))
		return domain.New(domain.CodeUpstreamUnavailable, opts...)
	default:
		// Other 4xx: the client's request was bad; never cooldown or retry.
		opts = append(opts, domain.WithScope(domain.ScopeRequest),
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}))
		return domain.New(domain.CodeBadUpstreamResponse, opts...)
	}
}

// now returns the injected clock or the wall clock.
func (e *Executor) now() time.Time {
	if e.deps.Clock != nil {
		return e.deps.Clock.Now()
	}
	return time.Now()
}
