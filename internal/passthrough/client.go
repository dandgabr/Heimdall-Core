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
	"net/url"
	"strconv"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
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

// Client is the upstream HTTP client. Its transport is supplied by the single
// egress policy (ADR-SEC-05); it is a plain contracts.HTTPDoer so a test can
// inject a fake without a network.
type Client struct {
	baseURL     string
	apiKey      string
	maxResponse int64
	http        contracts.HTTPDoer
}

// NewClient builds the upstream client through the single egress policy
// (ADR-SEC-05). The passthrough does NOT build an http.Client itself: it passes
// an EgressSpec to internal/egress, which applies TLS verification, the SSRF
// dial-time denylist, redirect blocking and the per-phase timeouts.
//
// The client deliberately has NO http.Client.Timeout: a global timeout would
// abort long-lived SSE streams mid-flight. TTFT is bounded by the spec's
// ResponseHeaderTimeout; the total deadline comes from the caller's context.
func NewClient(cfg ClientConfig) (*Client, error) {
	maxResponse := cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}

	doer, err := egress.New().Client(contracts.EgressSpec{
		BaseURL:               cfg.BaseURL,
		AllowLoopback:         egress.IsLoopbackLiteral(hostOf(cfg.BaseURL)),
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		MaxResponseBytes:      maxResponse,
		FollowRedirects:       false,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		baseURL:     cfg.BaseURL,
		apiKey:      cfg.APIKey,
		maxResponse: maxResponse,
		http:        doer,
	}, nil
}

// hostOf extracts the hostname from a raw URL. A parse failure yields "", which
// IsLoopbackLiteral rejects, so a malformed URL never unlocks the loopback
// exception.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
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
