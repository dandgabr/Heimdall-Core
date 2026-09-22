package cloudcode

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
)

// --- fakes ---

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{}

func (fakeIDs) NewRequestID() domain.RequestID { return "req" }

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

type fakeEgress struct{ doer contracts.HTTPDoer }

func (f fakeEgress) Client(contracts.EgressSpec) (contracts.HTTPDoer, error) { return f.doer, nil }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type openerFunc func(string) ([]byte, error)

func (f openerFunc) Open(s string) ([]byte, error) { return f(s) }

func testDeps(doer contracts.HTTPDoer) contracts.ExecutorDeps {
	return contracts.ExecutorDeps{
		Clock:    fakeClock{t: time.Unix(1000, 0)},
		IDs:      fakeIDs{},
		Redactor: fakeRedactor{},
		Secrets:  openerFunc(func(string) ([]byte, error) { return []byte("token-xyz"), nil }),
		Egress:   fakeEgress{doer: doer},
	}
}

// antigravityDescriptor is the real descriptor the executor obfuscates with.
func antigravityDescriptor() contracts.ProviderDescriptor {
	return contracts.ProviderDescriptor{
		ID:       "antigravity",
		Protocol: contracts.WireCloudCode,
		Obfuscation: contracts.Obfuscation{
			UserAgent:         "antigravity/ide/2.11.0 darwin/arm64",
			RequiresUserAgent: true,
			PromptRewrites: []contracts.PromptRewrite{
				{From: "You are a Claude agent, built on Anthropic's Claude Agent SDK.", To: ""},
				{From: "opencode", To: "antigravity"},
			},
			ToolCloaking: &contracts.ToolCloaking{
				NameSuffix: "_ide",
				DecoyTools: []contracts.ToolDecoy{
					{Name: "browser_subagent", Description: "This tool is currently unavailable."},
				},
			},
			SyntheticProject: true,
		},
	}
}

// oauthCred is an Antigravity OAuth credential with a known project.
func oauthCred() contracts.Credential {
	return contracts.Credential{
		ID: "cred-1", Provider: "antigravity", AuthMode: contracts.AuthOAuth,
		Meta:   contracts.AccountMeta{Project: "proj-abc"},
		Sealed: []byte("enc:v1:x:y:z"),
	}
}

func mustExecutor(t *testing.T, cfg Config, deps contracts.ExecutorDeps) *Executor {
	t.Helper()
	e, err := New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// captureExecutor returns an executor whose doer records the last request body.
func captureExecutor(t *testing.T, resp *http.Response) (*Executor, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		cap.header = r.Header.Clone()
		cap.url = r.URL.String()
		body, _ := io.ReadAll(r.Body)
		cap.body = body
		return resp, nil
	})
	e := mustExecutor(t, Config{Family: "antigravity", BaseURL: "https://daily-cloudcode-pa.googleapis.com", Descriptor: antigravityDescriptor()}, testDeps(doer))
	return e, cap
}

type capturedRequest struct {
	header http.Header
	url    string
	body   []byte
}

// geminiResponse builds a CloudCode-wrapped non-streaming response.
func geminiResponse(text string) *http.Response {
	payload := `{"response":{"candidates":[{"content":{"parts":[{"text":"` + text + `"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"totalTokenCount":5}}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(payload)),
	}
}

func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}

// --- envelope ---

// TestEnvelopeShapeAndRequestID pins the CloudCode envelope: project, model,
// userAgent, requestId in the `agent/...` shape, and a request object.
func TestEnvelopeShapeAndRequestID(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))

	canonical := `{"model":"gemini-3.5-flash","messages":[{"role":"user","content":"hello"}]}`
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "gemini-3.5-flash"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(cap.body, &env); err != nil {
		t.Fatalf("envelope not JSON: %v\n%s", err, cap.body)
	}
	var project, model, ua, requestID string
	_ = json.Unmarshal(env["project"], &project)
	_ = json.Unmarshal(env["model"], &model)
	_ = json.Unmarshal(env["userAgent"], &ua)
	_ = json.Unmarshal(env["requestId"], &requestID)

	if project != "proj-abc" {
		t.Errorf("project = %q, want the credential's project", project)
	}
	if model != "gemini-3.5-flash" {
		t.Errorf("model = %q", model)
	}
	if ua != "antigravity" {
		t.Errorf("userAgent = %q", ua)
	}
	if !looksLikeRequestID(requestID) {
		t.Errorf("requestId = %q, want agent/<conversation>/<ts>/<trajectory>/<step>", requestID)
	}
	if _, ok := env["request"]; !ok {
		t.Error("envelope missing request object")
	}
}

// TestRequestIDIsDeterministic proves the same inputs yield the same id (no
// random draw).
func TestRequestIDIsDeterministic(t *testing.T) {
	cred := oauthCred()
	req := contracts.WireRequest{Body: []byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`), Model: "m"}
	a := buildRequestID(antigravityDescriptor(), cred, req, "sess", time.Unix(0, 42))
	b := buildRequestID(antigravityDescriptor(), cred, req, "sess", time.Unix(0, 42))
	if a != b {
		t.Fatalf("requestId drifted: %q vs %q", a, b)
	}
	if !looksLikeRequestID(a) {
		t.Fatalf("requestId %q does not match the shape", a)
	}
}

// TestSyntheticProjectWhenMissing proves a missing project is derived
// deterministically (SyntheticProject), not left empty.
func TestSyntheticProjectWhenMissing(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))
	cred := oauthCred()
	cred.Meta.Project = "" // no loadCodeAssist project
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, cred); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var env map[string]json.RawMessage
	_ = json.Unmarshal(cap.body, &env)
	var project string
	_ = json.Unmarshal(env["project"], &project)
	if project == "" {
		t.Fatal("synthetic project was not injected")
	}
	// Deterministic for the same credential.
	want := e.syntheticProjectFor(cred)
	if project != want {
		t.Fatalf("project = %q, want %q", project, want)
	}
}

// --- obfuscation ---

// TestUserAgentHeaderIsObfuscated proves the UA header is the descriptor's.
func TestUserAgentHeaderIsObfuscated(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := cap.header.Get("User-Agent"); got != "antigravity/ide/2.11.0 darwin/arm64" {
		t.Fatalf("User-Agent = %q", got)
	}
	if got := cap.header.Get("Authorization"); got != "Bearer token-xyz" {
		t.Fatalf("Authorization = %q", got)
	}
}

// TestPromptRewriteApplied proves competing branding is rewritten in the system
// instruction.
func TestPromptRewriteApplied(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))
	canonical := `{"model":"m","messages":[{"role":"system","content":"You are a Claude agent, built on Anthropic's Claude Agent SDK. opencode rocks"},{"role":"user","content":"hi"}]}`
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "m"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	body := string(cap.body)
	if strings.Contains(body, "You are a Claude agent") {
		t.Error("Claude branding leaked into the upstream body")
	}
	if strings.Contains(body, "opencode") {
		t.Error("opencode branding leaked into the upstream body")
	}
	if !strings.Contains(body, "antigravity rocks") {
		t.Errorf("opencode was not rewritten to antigravity: %s", body)
	}
}

// TestToolCloakingAndUncloak proves client tools are suffixed, decoys injected,
// and the response tool name is reverted.
func TestToolCloakingAndUncloak(t *testing.T) {
	// Response carries the cloaked tool name get_weather_ide.
	payload := `{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather_ide","args":{"city":"SP"}}}]},"finishReason":"STOP"}]}}`
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(payload))}
	e, cap := captureExecutor(t, resp)

	canonical := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{}}}}]}`
	out, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "m"}, oauthCred())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// The upstream body must carry the suffixed name + the decoy.
	body := string(cap.body)
	if !strings.Contains(body, "get_weather_ide") {
		t.Errorf("tool not cloaked: %s", body)
	}
	if !strings.Contains(body, "browser_subagent") {
		t.Errorf("decoy tool not injected: %s", body)
	}
	// The response must be uncloaked back to get_weather.
	if !strings.Contains(string(out.Body), "get_weather") || strings.Contains(string(out.Body), "get_weather_ide") {
		t.Errorf("response not uncloaked: %s", out.Body)
	}
}

// TestBlacklistedFieldsStripped proves the Google-rejected thinking fields never
// reach the upstream body.
func TestBlacklistedFieldsStripped(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))
	canonical := `{"model":"m","messages":[{"role":"user","content":"hi"}],"output_config":{"x":1},"thinking":{"type":"enabled"},"reasoning_effort":"high","reasoning":{"effort":"high"},"enable_thinking":true,"thinking_budget":1024,"thinkingConfig":{"x":1}}`
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "m"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	body := string(cap.body)
	for _, field := range blacklistedFields {
		if strings.Contains(body, `"`+field+`"`) {
			t.Errorf("blacklisted field %q leaked into the upstream body: %s", field, body)
		}
	}
}

// TestStreamOptionsOnlyInStream proves stream_options is dropped for a
// non-streaming call and kept for a streaming one.
func TestStreamOptionsOnlyInStream(t *testing.T) {
	canonical := `{"model":"m","messages":[],"stream_options":{"include_usage":true}}`

	// Non-streaming: dropped.
	e, cap := captureExecutor(t, geminiResponse("hi"))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "m", Stream: false}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if strings.Contains(string(cap.body), "stream_options") {
		t.Errorf("stream_options leaked in a non-streaming call: %s", cap.body)
	}
}

// --- non-stream Do ---

func TestDoReturnsCanonicalResponse(t *testing.T) {
	e, _ := captureExecutor(t, geminiResponse("hello world"))
	resp, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || !strings.Contains(string(resp.Body), "hello world") {
		t.Fatalf("resp = %+v", resp)
	}
}

// TestDoImageModelNonStreamStillGenerateContent proves image models never use
// the streaming path.
func TestDoImageModelNonStreamStillGenerateContent(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("img"))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"gemini-3.1-flash-image","messages":[]}`), Model: "gemini-3.1-flash-image"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !strings.Contains(cap.url, "v1internal:generateContent") {
		t.Errorf("url = %q, want generateContent", cap.url)
	}
}

// --- maxOutputTokens cap ---

func TestMaxOutputTokensCapped(t *testing.T) {
	e, cap := captureExecutor(t, geminiResponse("hi"))
	canonical := `{"model":"m","messages":[],"max_tokens":100000}`
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(canonical), Model: "m"}, oauthCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var env struct {
		Request struct {
			GenerationConfig struct {
				MaxOutputTokens int `json:"maxOutputTokens"`
			} `json:"generationConfig"`
		} `json:"request"`
	}
	if err := json.Unmarshal(cap.body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Request.GenerationConfig.MaxOutputTokens != maxOutputTokensCap {
		t.Fatalf("maxOutputTokens = %d, want %d", env.Request.GenerationConfig.MaxOutputTokens, maxOutputTokensCap)
	}
}

// --- errors ---

func TestErrorMappingTable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("429 with Retry-After header", func(t *testing.T) {
		h := http.Header{"Retry-After": {"120"}}
		de := mapHTTPError(429, h, nil, now)
		if de.Code != domain.CodeUpstreamUnavailable || !de.Retryable || de.Scope != domain.ScopeCredential {
			t.Fatalf("err = %+v", de)
		}
		if de.RetryAfter != 120*time.Second {
			t.Fatalf("RetryAfter = %v, want 120s", de.RetryAfter)
		}
	})

	t.Run("429 with reset message", func(t *testing.T) {
		de := mapHTTPError(429, http.Header{}, []byte(`Your quota will reset after 2h7m23s`), now)
		want := 2*time.Hour + 7*time.Minute + 23*time.Second
		if de.RetryAfter != want {
			t.Fatalf("RetryAfter = %v, want %v", de.RetryAfter, want)
		}
		if !de.Retryable || de.Scope != domain.ScopeCredential {
			t.Fatalf("429 attributes = %+v", de)
		}
	})

	t.Run("429 x-ratelimit-reset-after", func(t *testing.T) {
		de := mapHTTPError(429, http.Header{"X-Ratelimit-Reset-After": {"45"}}, nil, now)
		if de.RetryAfter != 45*time.Second {
			t.Fatalf("RetryAfter = %v", de.RetryAfter)
		}
	})

	t.Run("503 transient retryable provider", func(t *testing.T) {
		de := mapHTTPError(503, http.Header{}, []byte("high traffic"), now)
		if de.Code != domain.CodeUpstreamUnavailable || !de.Retryable || de.Scope != domain.ScopeProvider {
			t.Fatalf("err = %+v", de)
		}
	})

	t.Run("400 client request scope", func(t *testing.T) {
		de := mapHTTPError(400, http.Header{}, []byte("bad input"), now)
		if de.Code != domain.CodeBadUpstreamResponse || de.Retryable || de.Scope != domain.ScopeRequest {
			t.Fatalf("err = %+v", de)
		}
	})
}

func TestTransportErrorPreservesEgressDenial(t *testing.T) {
	denied := domain.New(domain.CodeUpstreamDestinationDenied,
		domain.WithHTTPStatus(502), domain.WithScope(domain.ScopeProvider))
	wrapped := &urlError{denied}
	got := transportError(wrapped)
	if got.Code != domain.CodeUpstreamDestinationDenied || got.Retryable {
		t.Fatalf("egress denial reclassified: %+v", got)
	}
}

// urlError mimics net/url.Error's wrapping so errors.As unwraps the typed error.
type urlError struct{ inner error }

func (e *urlError) Error() string { return e.inner.Error() }
func (e *urlError) Unwrap() error { return e.inner }

// --- streaming (real egress + httptest) ---

func TestDoStreamSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "streamGenerateContent") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		for _, frame := range []string{
			`data: {"response":{"candidates":[{"content":{"parts":[{"text":"Hel"}]}}]}}` + "\n\n",
			`data: {"response":{"candidates":[{"content":{"parts":[{"text":"lo"}]}}]}}` + "\n\n",
			"data: [DONE]\n\n",
		} {
			_, _ = w.Write([]byte(frame))
			flusher.Flush()
		}
	}))
	defer srv.Close()

	e := loopbackExecutor(t, srv, 0)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"gemini-3.5-flash","messages":[]}`), Model: "gemini-3.5-flash", Stream: true}, oauthCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	var got strings.Builder
	for {
		ch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		// Each chunk is canonical JSON with the text.
		if !strings.Contains(string(ch.Data), "Hel") && !strings.Contains(string(ch.Data), "lo") {
			t.Errorf("unexpected chunk: %s", ch.Data)
		}
		got.WriteString(string(ch.Data))
	}
	if !strings.Contains(got.String(), "Hel") || !strings.Contains(got.String(), "lo") {
		t.Fatalf("stream output missing text: %s", got.String())
	}
}

// TestDoStreamImageModelNonStream proves an image model goes to generateContent
// and yields a one-chunk stream.
func TestDoStreamImageModelNonStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "generateContent") {
			t.Errorf("image model used %q, want generateContent", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"candidates":[{"content":{"parts":[{"text":"png"}]},"finishReason":"STOP"}]}}`))
	}))
	defer srv.Close()

	e := loopbackExecutor(t, srv, 0)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"gemini-3.1-flash-image","messages":[]}`), Model: "gemini-3.1-flash-image", Stream: true}, oauthCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	ch, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !strings.Contains(string(ch.Data), "png") {
		t.Fatalf("chunk = %s", ch.Data)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
}

func TestDoStreamPreCommitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte("capacity"))
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 0)
	_, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred())
	if err == nil || !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v, want upstream_unavailable", err)
	}
}

// --- helpers ---

func loopbackExecutor(t *testing.T, srv *httptest.Server, idle time.Duration) *Executor {
	t.Helper()
	deps := testDeps(nil)
	deps.Egress = egress.New()
	deps.Secrets = openerFunc(func(string) ([]byte, error) { return []byte("token-xyz"), nil })
	e, err := New(Config{
		Family: "antigravity", BaseURL: srv.URL, AllowLoopback: true,
		IdleTimeout: idle, Descriptor: antigravityDescriptor(),
	}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// TestNewRejectsBadConfig covers the constructor guards.
func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{BaseURL: "https://x"}, contracts.ExecutorDeps{}); err == nil {
		t.Error("missing deps accepted")
	}
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))
	if _, err := New(Config{}, deps); err == nil {
		t.Error("empty base url accepted")
	}
}

// TestCountTokensUnavailable covers the refusal.
func TestCountTokensUnavailable(t *testing.T) {
	e := mustExecutor(t, Config{Family: "antigravity", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeProviderNoExecutor) {
		t.Fatalf("err = %v", err)
	}
}

// TestUncloakToolNamesParallel covers the reverse map over parallel calls.
func TestUncloakToolNamesParallel(t *testing.T) {
	chunk := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"a_ide"}},{"index":1,"function":{"name":"b_ide"}},{"index":2,"function":{"name":"decoy"}}]}}]}`
	out, err := uncloakToolNames([]byte(chunk), map[string]string{"a_ide": "a", "b_ide": "b"})
	if err != nil {
		t.Fatalf("uncloak: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"name":"a"`) || !strings.Contains(s, `"name":"b"`) {
		t.Fatalf("parallel names not uncloaked: %s", s)
	}
	if !strings.Contains(s, `"name":"decoy"`) {
		t.Fatalf("unknown name was dropped: %s", s)
	}
}

// TestUncloakNoMapIsIdentity covers the empty-map fast path.
func TestUncloakNoMapIsIdentity(t *testing.T) {
	in := []byte(`{"choices":[]}`)
	out, err := uncloakToolNames(in, nil)
	if err != nil || string(out) != string(in) {
		t.Fatalf("out = %s, %v", out, err)
	}
}

// TestUncloakMalformedReturnsError covers the JSON error branch.
func TestUncloakMalformedReturnsError(t *testing.T) {
	if _, err := uncloakToolNames([]byte("{"), map[string]string{"a_ide": "a"}); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}

// TestSSEIdleTimeoutNoLeak proves the idle watcher terminates and no goroutine
// leaks (same invariant as the OpenAI executor).
func TestSSEIdleTimeoutNoLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`data: {"response":{"candidates":[{"content":{"parts":[{"text":"a"}]}}]}}` + "\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done() // stall
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 200*time.Millisecond)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m", Stream: true}, oauthCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Recv(); done <- err }()
	select {
	case err := <-done:
		if !hasCode(err, domain.CodeUpstreamTimeout) {
			t.Fatalf("idle Recv = %v, want upstream_timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Recv did not return on idle timeout")
	}
}

// TestSSEStreamCloseIdempotent covers Close from many goroutines.
func TestSSEStreamCloseIdempotent(t *testing.T) {
	s := &sseStream{
		body:    io.NopCloser(strings.NewReader("")),
		headers: http.Header{},
		ctx:     context.Background(),
		scanner: bufio.NewScanner(strings.NewReader("")),
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Close() }()
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestSingleChunkStream covers the non-stream wrapper directly.
func TestSingleChunkStream(t *testing.T) {
	s := newSingleChunkStream(200, http.Header{"X": {"1"}}, []byte("body"))
	if s.Headers().Get("X") != "1" {
		t.Fatal("headers not exposed")
	}
	ch, err := s.Recv()
	if err != nil || string(ch.Data) != "body" {
		t.Fatalf("%+v %v", ch, err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
