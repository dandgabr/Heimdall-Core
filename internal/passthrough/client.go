// Package passthrough is the minimal end-to-end upstream path built in F0.
//
// It forwards OpenAI-compatible chat completion requests to a single hardcoded
// upstream and relays the reply, streaming or buffered. Its purpose is to prove
// the streaming skeleton (commit-on-first-byte, transport-level timeouts,
// context cancellation, bounded channels) before authentication and provider
// complexity arrive in F1/F2.
package passthrough

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Request and response limits. A router in front of a provider must not let an
// unbounded body exhaust memory on either side of the hop.
const (
	// MaxRequestBytes bounds the forwarded request body.
	MaxRequestBytes = 8 << 20 // 8 MiB
	// DefaultMaxResponseBytes bounds a buffered (non-stream) upstream response.
	// Streaming responses are bounded per-event by the SSE relay instead.
	DefaultMaxResponseBytes = 32 << 20 // 32 MiB
	// MaxErrorBodyBytes bounds how much of an upstream error we read.
	MaxErrorBodyBytes = 8 << 10 // 8 KiB
)

// ClientConfig configures the upstream client.
type ClientConfig struct {
	// BaseURL is the upstream root, e.g. https://api.openai.com/v1.
	BaseURL string
	// APIKey is the upstream credential. It is never logged and never echoed.
	APIKey string
	// ResponseHeaderTimeout bounds time-to-first-byte (TTFT). This is the
	// correct place to bound a streaming call: it limits how long we wait for
	// the upstream to start responding without capping the total stream
	// duration.
	ResponseHeaderTimeout time.Duration
	// MaxResponseBytes bounds a buffered upstream response. Zero means
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

// Client is the upstream HTTP client.
type Client struct {
	baseURL     string
	apiKey      string
	maxResponse int64
	http        *http.Client
}

// NewClient builds the upstream client, validating the destination first.
//
// The http.Client deliberately has NO Timeout field set: a global Client.Timeout
// would abort long-lived SSE streams mid-flight. The per-phase bounds live on
// the Transport instead (ResponseHeaderTimeout here; idle and total deadlines
// are layered on by the caller's context in later phases).
//
// Egress controls (ADR-003):
//   - HTTPS is mandatory, except for an explicit loopback IP literal (a local
//     model server); the policy is checked before the client exists;
//   - a Dialer Control hook rejects loopback/private/link-local/metadata
//     destinations after resolution, defeating DNS rebinding;
//   - CheckRedirect refuses every redirect, so a 30x cannot move the request to
//     an unvalidated destination.
func NewClient(cfg ClientConfig) (*Client, error) {
	allowLoopback, err := validateUpstreamURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	maxResponse := cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   ssrfControl(allowLoopback),
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
	}
	return &Client{
		baseURL:     cfg.BaseURL,
		apiKey:      cfg.APIKey,
		maxResponse: maxResponse,
		http: &http.Client{
			Transport: transport,
			// Never follow a redirect: an upstream 30x could otherwise send the
			// request (and the Authorization header) to a different host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// endpoint returns the chat completions URL.
func (c *Client) endpoint() string {
	base := c.baseURL
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + "/chat/completions"
}

// newRequest builds the upstream request from the raw body. The body is
// forwarded verbatim so unknown fields survive; the caller has already parsed
// only the fields it needs (model, stream).
func (c *Client) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return req, nil
}

// Complete performs a non-streaming call. It buffers and returns the upstream
// body. An upstream non-2xx is returned as a DomainError so the API layer can
// still emit a proper HTTP error (nothing has been committed downstream).
//
// The body is read through an io.LimitReader capped at maxResponse+1: reading
// one byte past the limit is how an over-limit response is told apart from one
// that fits exactly. io.ReadAll alone would buffer an unbounded body.
func (c *Client) Complete(ctx context.Context, body []byte) ([]byte, error) {
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, transportError(err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, upstreamError(resp)
	}

	limited := io.LimitReader(resp.Body, c.maxResponse+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, transportError(err)
	}
	if int64(len(out)) > c.maxResponse {
		return nil, domain.New(domain.CodeUpstreamResponseTooLarge,
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.WithParams(map[string]string{"limit": strconv.FormatInt(c.maxResponse, 10)}),
		)
	}
	return out, nil
}

// transportError maps a transport-level failure to a DomainError. Timeouts and
// context cancellation are distinguished so the caller can decide whether to
// retry or to stop because the client hung up.
func transportError(err error) *domain.DomainError {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.New(domain.CodeUpstreamTimeout,
			domain.WithHTTPStatus(http.StatusGatewayTimeout),
			domain.WithCause(err),
		)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return domain.New(domain.CodeUpstreamTimeout,
			domain.WithHTTPStatus(http.StatusGatewayTimeout),
			domain.WithCause(err),
		)
	}
	return domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithCause(err),
	)
}

// upstreamError translates an upstream non-2xx response. The upstream body is
// read only up to MaxErrorBodyBytes and is never returned verbatim to the
// client (it may echo the credential or upstream internals).
func upstreamError(resp *http.Response) *domain.DomainError {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBodyBytes))

	code := domain.CodeUpstreamUnavailable
	opts := []domain.Option{
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithParams(map[string]string{"status": http.StatusText(resp.StatusCode)}),
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		code = domain.CodeUpstreamUnavailable
		opts = append(opts, domain.Retry(),
			domain.WithParams(map[string]string{"status": "429"}))
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		code = domain.CodeUpstreamTimeout
		opts = append(opts, domain.Retry())
	case http.StatusUnauthorized, http.StatusForbidden:
		opts = append(opts, domain.WithHTTPStatus(http.StatusBadGateway))
	}
	return domain.New(code, opts...)
}

// readStreamFlag extracts model and stream from a raw body without disturbing
// the forwarded bytes.
func readStreamFlag(body []byte) (model string, stream bool, err error) {
	var meta struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", false, err
	}
	return meta.Model, meta.Stream, nil
}
