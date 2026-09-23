package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/egress"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// HTTPEmbedder is the OPT-IN external embedding engine (ADR-SEC-07 §5). The
// local-first default is NO embedder: with cfg unset, NewHTTPEmbedder returns
// nil and the family stays FTS5-only. Constructing one is the operator's
// explicit opt-in, and every call:
//
//   - REDACTS the content through the central redactor BEFORE any byte leaves
//     the process (pseudonymization at the egress boundary, SEC-07 §5);
//   - uses the single egress policy for its transport (ADR-SEC-05: HTTPS,
//     dial-time SSRF guard, no redirects, bounded TTFT — never a raw
//     http.Client);
//   - sends the API key from the configured ENVIRONMENT VARIABLE name, never
//     from config bytes, and never logs it.
type HTTPEmbedder struct {
	model    string
	dim      int
	endpoint string
	doer     contracts.HTTPDoer
	key      func() string
}

// EmbedderConfig configures the opt-in engine.
type EmbedderConfig struct {
	// BaseURL is the embeddings API root (must be HTTPS per ADR-SEC-05).
	BaseURL string
	// Model is the provider's embedding model identifier.
	Model string
	// APIKeyEnv names the environment variable holding the API key. The key
	// itself never appears in config or logs.
	APIKeyEnv string
	// Dim is the expected vector dimensionality; a mismatched response is an
	// error, not a silent truncation. Must be positive.
	Dim int
	// Timeout bounds time-to-first-byte of the call. Zero → 10s.
	Timeout time.Duration
	// Policy is the egress authority. Nil → the default egress policy.
	Policy contracts.EgressPolicy
	// Doer overrides the policy-built client entirely (test seam).
	Doer contracts.HTTPDoer
}

// NewHTTPEmbedder builds the engine, or nil when the opt-in is incomplete —
// a base URL, a model and a positive dimension are what "explicitly enabled"
// means; anything less stays off.
func NewHTTPEmbedder(cfg EmbedderConfig) *HTTPEmbedder {
	if cfg.BaseURL == "" || cfg.Model == "" || cfg.Dim <= 0 {
		return nil
	}
	e := &HTTPEmbedder{
		model:    cfg.Model,
		dim:      cfg.Dim,
		endpoint: strings.TrimSuffix(cfg.BaseURL, "/") + "/embeddings",
		key:      func() string { return os.Getenv(cfg.APIKeyEnv) },
	}
	if cfg.Doer != nil {
		e.doer = cfg.Doer
		return e
	}
	policy := cfg.Policy
	if policy == nil {
		policy = egress.New()
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	doer, err := policy.Client(contracts.EgressSpec{
		BaseURL:               cfg.BaseURL,
		ResponseHeaderTimeout: timeout,
	})
	if err != nil {
		return nil // a policy-invalid destination keeps the engine OFF
	}
	e.doer = doer
	return e
}

// ID implements contracts.Embedder.
func (e *HTTPEmbedder) ID() string { return "http:" + e.model }

// Dim implements contracts.Embedder.
func (e *HTTPEmbedder) Dim() int { return e.dim }

// embedRequest is the wire shape the engine sends.
type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// embedResponse is the wire shape the engine accepts.
type embedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
}

// Embed implements contracts.Embedder. The content is redacted BEFORE the
// request is built, so no provider ever sees raw prompt material. Both the
// payload marshal and the request construction use only locally-controlled,
// valid inputs (a struct of strings/slices and a constant method over a
// validated URL), so neither can fail and neither carries an error branch.
func (e *HTTPEmbedder) Embed(ctx context.Context, content string) ([]float32, error) {
	redacted := i18n.RedactString(content)
	payload, _ := json.Marshal(embedRequest{Model: e.model, Input: []string{redacted}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if key := e.key(); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := e.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("memory embedder: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("memory embedder: status %d", resp.StatusCode)
	}
	var decoded embedResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("memory embedder: %w", err)
	}
	if len(decoded.Data) == 0 {
		return nil, fmt.Errorf("memory embedder: empty data")
	}
	vec := decoded.Data[0].Embedding
	if len(vec) != e.dim {
		return nil, fmt.Errorf("memory embedder: dim %d, want %d", len(vec), e.dim)
	}
	return vec, nil
}

var _ contracts.Embedder = (*HTTPEmbedder)(nil)
