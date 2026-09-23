// Package cloudcode implements the Google CloudCode Assist transport+auth for
// the Antigravity connector (ADR-0003). It is a contracts.Executor like the
// OpenAI-compatible one, but speaks the CloudCode wire dialect:
//
//	POST {base}/v1internal:generateContent
//	POST {base}/v1internal:streamGenerateContent?alt=sse
//
// with an envelope of {project, model, userAgent, requestId, request:{...}}.
//
// SCOPE: transport + auth + the CloudCode envelope. The OpenAI(canonical) to
// Gemini body translation reuses the pure Gemini translator; the per-provider
// OBFUSCATION (UA, prompt rewrites, tool cloaking, synthetic project) is applied
// here from the descriptor, exactly as ADR-0003 requires ("applied by the
// family's executor, never globally").
//
// The executor never builds an http.Client: the client comes from
// contracts.ExecutorDeps.Egress (ADR-SEC-05). It never logs or echoes the
// credential.
package cloudcode

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/obfuscate"
	"github.com/dandgabr/heimdall-core/internal/translators"
)

// Endpoints and limits.
const (
	// DefaultBaseURL is the Antigravity chat host (daily). The project-discovery
	// calls live on cloudcode-pa; see the auth flow.
	DefaultBaseURL = "https://daily-cloudcode-pa.googleapis.com"
	// maxOutputTokensCap is the Antigravity output cap.
	maxOutputTokensCap = 64000
	// maxResponseBytes bounds a buffered response.
	maxResponseBytes = 32 << 20
	// maxErrorBodyBytes bounds how much of an error body is read.
	maxErrorBodyBytes = 8 << 10
	// DefaultResponseHeaderTimeout bounds TTFT.
	DefaultResponseHeaderTimeout = 60 * time.Second
)

// Config configures the CloudCode executor. It is DATA.
type Config struct {
	// Family is the provider family identity.
	Family domain.ProviderID
	// BaseURL is the chat root, e.g. https://daily-cloudcode-pa.googleapis.com.
	BaseURL string
	// AllowLoopback unlocks the loopback exception for tests.
	AllowLoopback bool
	// ResponseHeaderTimeout bounds TTFT.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds the gap between stream chunks.
	IdleTimeout time.Duration
	// Descriptor is the provider descriptor: it carries the Obfuscation layer
	// (ADR-0003 §1), which this executor applies.
	Descriptor contracts.ProviderDescriptor
}

// Executor is the CloudCode contracts.Executor.
type Executor struct {
	cfg  Config
	deps contracts.ExecutorDeps
	doer contracts.HTTPDoer
	// translator is the pure OpenAI(canonical) <-> Gemini(canonical) translator
	// used to build the CloudCode request body and decode responses.
	translator contracts.Translator
}

var _ contracts.Executor = (*Executor)(nil)

// New builds the executor, constructing the transport through the egress policy
// (never inline).
func New(cfg Config, deps contracts.ExecutorDeps) (*Executor, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		return nil, domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithParams(map[string]string{"reason": "cloudcode: empty base url"}),
		)
	}
	headerTimeout := cfg.ResponseHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = DefaultResponseHeaderTimeout
	}

	doer, err := deps.Egress.Client(contracts.EgressSpec{
		BaseURL:               cfg.BaseURL,
		AllowLoopback:         cfg.AllowLoopback,
		ResponseHeaderTimeout: headerTimeout,
		IdleTimeout:           cfg.IdleTimeout,
		FollowRedirects:       false,
		MaxResponseBytes:      maxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	return &Executor{cfg: cfg, deps: deps, doer: doer, translator: translators.GeminiToOpenAI{}}, nil
}

// Family implements contracts.Executor.
func (e *Executor) Family() domain.ProviderID { return e.cfg.Family }

// CountTokens implements contracts.Executor: CloudCode has no counting endpoint
// wired here, so it refuses rather than fabricating a number.
func (e *Executor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, domain.New(domain.CodeProviderNoExecutor,
		domain.WithHTTPStatus(http.StatusNotImplemented),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"provider": string(e.cfg.Family)}),
	)
}

// Do implements contracts.Executor: one non-streaming generateContent call.
func (e *Executor) Do(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.WireResponse, error) {
	env, err := e.buildEnvelope(req, cred, false)
	if err != nil {
		return contracts.WireResponse{}, err
	}
	// post already maps a non-2xx to a typed error, so a returned response is a
	// 2xx and the body is the payload.
	resp, err := e.post(ctx, e.endpoint("generateContent"), env, cred)
	if err != nil {
		return contracts.WireResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return contracts.WireResponse{}, transportError(err)
	}

	// The CloudCode response wraps the Gemini payload in {"response": {...}}.
	unwrapped := unwrapResponse(body)
	canonical, err := e.translator.ResponseFull(unwrapped, string(req.Model))
	if err != nil {
		return contracts.WireResponse{}, domain.New(domain.CodeBadUpstreamResponse,
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.WithScope(domain.ScopeProvider),
			domain.WithCause(err),
		)
	}
	// Revert any cloaked tool names in the response.
	canonical = e.uncloakResponse(canonical, env.toolMap)

	return contracts.WireResponse{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    canonical,
	}, nil
}

// DoStream implements contracts.Executor: one streamGenerateContent SSE call.
// Image models force non-stream (the provider rejects SSE for them).
func (e *Executor) DoStream(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	stream := req.Stream && !isImageModel(string(req.Model))
	env, err := e.buildEnvelope(req, cred, stream)
	if err != nil {
		return nil, err
	}

	var httpReq *http.Request
	if stream {
		httpReq, err = e.newRequest(ctx, e.endpoint("streamGenerateContent")+"?alt=sse", env, cred)
	} else {
		httpReq, err = e.newRequest(ctx, e.endpoint("generateContent"), env, cred)
	}
	if err != nil {
		return nil, err
	}

	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return nil, transportError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, mapHTTPError(resp.StatusCode, resp.Header, body, e.now())
	}

	if !stream {
		// A non-streaming model requested through DoStream: wrap the single
		// response as a one-chunk stream.
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, transportError(err)
		}
		canonical, err := e.translator.ResponseFull(unwrapResponse(body), string(req.Model))
		if err != nil {
			return nil, domain.New(domain.CodeBadUpstreamResponse,
				domain.WithHTTPStatus(http.StatusBadGateway),
				domain.WithScope(domain.ScopeProvider), domain.WithCause(err))
		}
		return newSingleChunkStream(resp.StatusCode, resp.Header, e.uncloakResponse(canonical, env.toolMap)), nil
	}

	s := &sseStream{
		body:        resp.Body,
		headers:     resp.Header,
		ctx:         ctx,
		idleTimeout: e.cfg.IdleTimeout,
		scanner:     bufio.NewScanner(resp.Body),
		translator:  e.translator,
		model:       string(req.Model),
		toolMap:     env.toolMap,
		now:         e.now,
	}
	s.scanner.Buffer(make([]byte, 0, 64<<10), maxStreamEventBytes)
	return s, nil
}

// endpoint joins the base URL with a v1internal method.
func (e *Executor) endpoint(method string) string {
	return strings.TrimRight(e.cfg.BaseURL, "/") + "/v1internal:" + method
}

// post sends a non-streaming request.
func (e *Executor) post(ctx context.Context, url string, env envelope, cred contracts.Credential) (*http.Response, error) {
	httpReq, err := e.newRequest(ctx, url, env, cred)
	if err != nil {
		return nil, err
	}
	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return nil, transportError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		_ = resp.Body.Close()
		return nil, mapHTTPError(resp.StatusCode, resp.Header, body, e.now())
	}
	return resp, nil
}

// newRequest builds the HTTP request with the envelope body, auth header and the
// obfuscated User-Agent. Before the sealed blob is opened, an expired OAuth
// credential is renewed through the optional Refresher port (BD02-1), so the
// bearer presented upstream is the persisted, refreshed token.
func (e *Executor) newRequest(ctx context.Context, url string, env envelope, cred contracts.Credential) (*http.Request, error) {
	cred = e.renewedCredential(ctx, cred)
	secret, err := openCredential(e.deps, cred)
	if err != nil {
		return nil, err
	}
	body, err := env.marshal()
	if err != nil {
		return nil, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The obfuscated UA (ADR-0003 §2), pinned even off macOS.
	if ua := obfuscate.UserAgent(e.cfg.Descriptor); ua != "" {
		httpReq.Header.Set("User-Agent", ua)
	}
	if secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+secret)
	}
	return httpReq, nil
}

// now returns the injected clock or the wall clock.
func (e *Executor) now() time.Time {
	if e.deps.Clock != nil {
		return e.deps.Clock.Now()
	}
	return time.Now()
}

// buildEnvelope assembles the CloudCode request envelope from the canonical
// request: translate to Gemini, apply the obfuscation, resolve the project, and
// derive a deterministic requestId.
func (e *Executor) buildEnvelope(req contracts.WireRequest, cred contracts.Credential, stream bool) (envelope, error) {
	canonical := req.Body
	// 1. Prompt rewrites on the canonical body (system branding).
	rewritten, err := obfuscate.Apply(e.cfg.Descriptor, canonical)
	if err != nil {
		return envelope{}, err
	}
	// 2. Tool cloaking on the canonical body; keep the reverse map.
	cloaked, toolMap, err := obfuscate.CloakTools(e.cfg.Descriptor, rewritten)
	if err != nil {
		return envelope{}, err
	}
	// 3. Translate the canonical (OpenAI-shaped) body to Gemini.
	gemini, err := e.translator.Request(cloaked, string(req.Model), stream)
	if err != nil {
		return envelope{}, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not build the upstream request"}),
		)
	}
	sessionID := deriveSessionID(cred, req)
	// 4. Clean Google-rejected fields, drop non-stream stream_options, set the
	// sessionId, and cap maxOutputTokens.
	request, err := cleanRequest(gemini, stream, sessionID)
	if err != nil {
		return envelope{}, err
	}

	project := cred.Meta.Project
	if project == "" {
		project = e.syntheticProjectFor(cred)
	}

	return envelope{
		Project:   project,
		Model:     string(req.Model),
		UserAgent: "antigravity",
		RequestID: buildRequestID(e.cfg.Descriptor, cred, req, sessionID, e.now()),
		Request:   request,
		SessionID: sessionID,
		toolMap:   toolMap,
	}, nil
}

// syntheticProjectFor returns the deterministic synthetic project id for a
// credential when the descriptor opts into SyntheticProject, or "" otherwise.
func (e *Executor) syntheticProjectFor(cred contracts.Credential) string {
	if !e.cfg.Descriptor.Obfuscation.SyntheticProject {
		return ""
	}
	return obfuscate.SyntheticProject(string(cred.ID))
}

// deriveSessionID derives a stable session id from the credential, never random.
func deriveSessionID(cred contracts.Credential, req contracts.WireRequest) string {
	seed := string(cred.ID)
	if seed == "" {
		seed = string(cred.Meta.Email)
	}
	if seed == "" {
		seed = string(req.Model)
	}
	// Reuse the pure, deterministic obfuscate derivation (a stable hash).
	return "session-" + obfuscate.SyntheticProject("cloudcode:session:"+seed)
}

// uncloakResponse reverts cloaked tool names in a canonical response body.
func (e *Executor) uncloakResponse(canonical []byte, toolMap map[string]string) []byte {
	if len(toolMap) == 0 || len(canonical) == 0 {
		return canonical
	}
	out, err := uncloakToolNames(canonical, toolMap)
	if err != nil {
		return canonical
	}
	return out
}

// isImageModel reports whether the model is an image-generation model, which
// must use non-streaming generateContent.
func isImageModel(model string) bool {
	m := strings.ToLower(model)
	return strings.Contains(m, "image") || strings.Contains(m, "imagen")
}
