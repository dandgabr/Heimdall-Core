package cloudcode

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/translators"
)

// --- constructor / simple accessors ---

func TestFamilyReportsID(t *testing.T) {
	e := mustExecutor(t, Config{Family: "antigravity", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if e.Family() != "antigravity" {
		t.Fatalf("Family = %q", e.Family())
	}
}

func TestNewEgressClientError(t *testing.T) {
	deps := testDeps(nil)
	deps.Egress = errorEgress{}
	if _, err := New(Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()}, deps); err == nil {
		t.Fatal("expected the egress build error")
	}
}

type errorEgress struct{}

func (errorEgress) Client(contracts.EgressSpec) (contracts.HTTPDoer, error) {
	return nil, domain.New(domain.CodeProviderInvalid, domain.WithHTTPStatus(500))
}

// --- credential ---

func TestOpenCredentialBranches(t *testing.T) {
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))

	if s, err := openCredential(deps, contracts.Credential{AuthMode: contracts.AuthNone}); err != nil || s != "" {
		t.Fatalf("AuthNone = %q, %v", s, err)
	}

	// Missing secret store.
	noSecret := deps
	noSecret.Secrets = nil
	if _, err := openCredential(noSecret, oauthCred()); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("missing store err = %v", err)
	}

	// Empty sealed blob.
	if _, err := openCredential(deps, contracts.Credential{AuthMode: contracts.AuthAPIKey}); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("empty sealed err = %v", err)
	}

	// Open failure.
	badOpen := deps
	badOpen.Secrets = openerFunc(func(string) ([]byte, error) { return nil, io.ErrUnexpectedEOF })
	if _, err := openCredential(badOpen, oauthCred()); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("open failure err = %v", err)
	}

	// Unknown mode.
	if _, err := openCredential(deps, contracts.Credential{AuthMode: contracts.AuthMode(99)}); !hasCode(err, domain.CodeCredentialInvalidAuthMode) {
		t.Fatalf("unknown mode err = %v", err)
	}
}

// --- transport errors ---

func TestTransportErrorBranches(t *testing.T) {
	if transportError(nil) != nil {
		t.Fatal("nil should map to nil")
	}
	// Generic retryable.
	de := transportError(io.ErrUnexpectedEOF)
	if de.Code != domain.CodeUpstreamUnavailable || !de.Retryable {
		t.Fatalf("generic = %+v", de)
	}
	// Timeout.
	if got := transportError(timeoutErr{}); got.Code != domain.CodeUpstreamTimeout || !got.Retryable {
		t.Fatalf("timeout = %+v", got)
	}
	// Context canceled (non-retryable path).
	if got := transportError(context.Canceled); got.Code != domain.CodeUpstreamTimeout {
		t.Fatalf("canceled = %+v", got)
	}
	// Non-policy domain error falls through to generic.
	other := domain.New(domain.CodeBadUpstreamResponse, domain.WithHTTPStatus(400))
	if egressPolicyError(other) != nil {
		t.Fatal("non-policy error treated as policy")
	}
	// Insecure URL is preserved.
	insecure := domain.New(domain.CodeUpstreamInsecureURL, domain.WithHTTPStatus(500))
	if got := transportError(insecure); got.Code != domain.CodeUpstreamInsecureURL {
		t.Fatalf("insecure = %+v", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// --- id + helpers ---

func TestLooksLikeRequestID(t *testing.T) {
	good := "agent/11111111-1111-5111-8111-111111111111/1700000000/22222222-2222-5222-8222-222222222222/3"
	if !looksLikeRequestID(good) {
		t.Fatal("valid id rejected")
	}
	for _, bad := range []string{
		"", "agent/a/b/c", "agent/a/notanum/c/1", "agent//1/c/1", "agent/a/1/c/notnum", "other/a/1/c/1",
	} {
		if looksLikeRequestID(bad) {
			t.Errorf("invalid id %q accepted", bad)
		}
	}
}

func TestContentCountBranches(t *testing.T) {
	if got := contentCount(nil); got != 1 {
		t.Errorf("nil = %d, want 1", got)
	}
	if got := contentCount([]byte("not json")); got != 1 {
		t.Errorf("invalid = %d, want 1", got)
	}
	if got := contentCount([]byte(`{"model":"m"}`)); got != 1 {
		t.Errorf("no messages = %d, want 1", got)
	}
	if got := contentCount([]byte(`{"messages":[]}`)); got != 1 {
		t.Errorf("empty messages = %d, want 1", got)
	}
	if got := contentCount([]byte(`{"messages":[{"role":"user"},{"role":"user"}]}`)); got != 2 {
		t.Errorf("two messages = %d, want 2", got)
	}
	// Non-array messages.
	if got := contentCount([]byte(`{"messages":"x"}`)); got != 1 {
		t.Errorf("non-array = %d, want 1", got)
	}
}

func TestMaxHelper(t *testing.T) {
	if max(3, 1) != 3 || max(1, 3) != 3 {
		t.Fatal("max wrong")
	}
}

func TestNowWallClock(t *testing.T) {
	e := &Executor{}
	if e.now().IsZero() {
		t.Fatal("now() returned zero")
	}
}

// --- envelope helpers ---

func TestDecodeObjectBranches(t *testing.T) {
	if decodeObject(nil) != nil {
		t.Fatal("nil should be nil")
	}
	if decodeObject([]byte("[]")) != nil {
		t.Fatal("array should be nil")
	}
	if decodeObject([]byte(`{"a":1}`)) == nil {
		t.Fatal("object should decode")
	}
}

func TestNumToIntBranches(t *testing.T) {
	if _, ok := numToInt([]byte(`"x"`)); ok {
		t.Fatal("string should not decode as int")
	}
	if n, ok := numToInt([]byte(`42`)); !ok || n != 42 {
		t.Fatal("int decode failed")
	}
}

func TestUnwrapResponseBranches(t *testing.T) {
	if got := unwrapResponse([]byte("not json")); string(got) != "not json" {
		t.Fatalf("passthrough = %s", got)
	}
	wrapped := unwrapResponse([]byte(`{"response":{"x":1}}`))
	if string(wrapped) != `{"x":1}` {
		t.Fatalf("unwrap = %s", wrapped)
	}
	// No response key: returned as-is.
	bare := unwrapResponse([]byte(`{"error":{"code":1}}`))
	if string(bare) != `{"error":{"code":1}}` {
		t.Fatalf("bare = %s", bare)
	}
}

func TestCleanRequestNonObject(t *testing.T) {
	out, err := cleanRequest([]byte(`[1,2]`), false, "sess")
	if err != nil || string(out) != "[1,2]" {
		t.Fatalf("non-object = %s, %v", out, err)
	}
}

func TestCleanRequestStripsAndInjectsSession(t *testing.T) {
	in := `{"thinking":{"x":1},"contents":[],"stream_options":{"include_usage":true}}`
	out, err := cleanRequest([]byte(in), false, "sess-1")
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out, &obj)
	if _, ok := obj["thinking"]; ok {
		t.Error("thinking not stripped")
	}
	if _, ok := obj["stream_options"]; ok {
		t.Error("stream_options not stripped for non-stream")
	}
	var sess string
	_ = json.Unmarshal(obj["sessionId"], &sess)
	if sess != "sess-1" {
		t.Errorf("sessionId = %q", sess)
	}
}

func TestCapMaxOutputTokensBranches(t *testing.T) {
	// No generationConfig.
	capMaxOutputTokens(map[string]json.RawMessage{})
	// generationConfig not an object.
	capMaxOutputTokens(map[string]json.RawMessage{"generationConfig": json.RawMessage(`[]`)})
	// No maxOutputTokens.
	capMaxOutputTokens(map[string]json.RawMessage{"generationConfig": json.RawMessage(`{}`)})
	// Non-int maxOutputTokens.
	capMaxOutputTokens(map[string]json.RawMessage{"generationConfig": json.RawMessage(`{"maxOutputTokens":"x"}`)})
	// Within cap.
	obj := map[string]json.RawMessage{"generationConfig": json.RawMessage(`{"maxOutputTokens":100}`)}
	capMaxOutputTokens(obj)
	var gen map[string]int
	_ = json.Unmarshal(obj["generationConfig"], &gen)
	if gen["maxOutputTokens"] != 100 {
		t.Fatalf("within-cap changed: %v", gen)
	}
}

// --- error parsing ---

func TestParseRetryAfterHeaderBranches(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if d := parseRetryAfterHeader("", now); d != 0 {
		t.Fatalf("empty = %v", d)
	}
	if d := parseRetryAfterHeader("-5", now); d != 0 {
		t.Fatalf("negative = %v", d)
	}
	if d := parseRetryAfterHeader("bogus", now); d != 0 {
		t.Fatalf("bogus = %v", d)
	}
	if d := parseRetryAfterHeader(now.Add(30*time.Second).UTC().Format(http.TimeFormat), now); d != 30*time.Second {
		t.Fatalf("future date = %v", d)
	}
	if d := parseRetryAfterHeader(now.Add(-time.Minute).UTC().Format(http.TimeFormat), now); d != 0 {
		t.Fatalf("past date = %v", d)
	}
}

func TestParseSecondsHeaderBranches(t *testing.T) {
	if d := parseSecondsHeader(""); d != 0 {
		t.Fatalf("empty = %v", d)
	}
	if d := parseSecondsHeader("abc"); d != 0 {
		t.Fatalf("nan = %v", d)
	}
	if d := parseSecondsHeader("0"); d != 0 {
		t.Fatalf("zero = %v", d)
	}
	if d := parseSecondsHeader("12"); d != 12*time.Second {
		t.Fatalf("ok = %v", d)
	}
}

func TestParseUnixResetHeaderBranches(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if d := parseUnixResetHeader("", now); d != 0 {
		t.Fatalf("empty = %v", d)
	}
	if d := parseUnixResetHeader("notnum", now); d != 0 {
		t.Fatalf("nan = %v", d)
	}
	if d := parseUnixResetHeader("1600000000", now); d != 0 {
		t.Fatalf("past = %v", d)
	}
	if d := parseUnixResetHeader("1700000060", now); d != 60*time.Second {
		t.Fatalf("future = %v", d)
	}
}

func TestParseRetryAfterXReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := http.Header{"X-Ratelimit-Reset": {"1700000090"}}
	if d := parseRetryAfter(h, "", now); d != 90*time.Second {
		t.Fatalf("x-ratelimit-reset = %v", d)
	}
}

func TestIsTransientBranches(t *testing.T) {
	for _, m := range []string{"high traffic", "capacity exceeded", "temporarily unavailable", "timeout while reading"} {
		if !isTransient(m) {
			t.Errorf("%q not transient", m)
		}
	}
	if isTransient("bad request") {
		t.Error("bad request marked transient")
	}
}

// --- executor paths ---

// TestDoBuildRequestError covers newRequest's build failure (control char URL).
func TestDoBuildRequestError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "http://exa mple.test", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, oauthCred()); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

// TestDoEnvelopeInvalidBody covers buildEnvelope's translate error path.
func TestDoEnvelopeInvalidBody(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte("{not json"), Model: "m"}, oauthCred()); err == nil {
		t.Fatal("invalid body accepted")
	}
}

// TestDoTransportError covers the doer transport failure.
func TestDoTransportError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestDoNon2xx covers Do's pre-commit error and body-read error.
func TestDoNon2xx(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("boom"))}, nil
		})))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestDoBodyReadError covers the read failure on a 2xx.
func TestDoBodyReadError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}, nil
		})))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errBody) Close() error             { return nil }

// TestDoBadUpstreamJSON covers ResponseFull's translate error.
func TestDoBadUpstreamJSON(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{"))}, nil
		})))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeBadUpstreamResponse) {
		t.Fatalf("err = %v", err)
	}
}

// TestDoAuthSecretMissing covers newRequest's credential failure.
func TestDoAuthSecretMissing(t *testing.T) {
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))
	deps.Secrets = nil
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()}, deps)
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("err = %v", err)
	}
}

// TestSyntheticProjectDisabled covers the SyntheticProject=false branch.
func TestSyntheticProjectDisabled(t *testing.T) {
	desc := antigravityDescriptor()
	desc.Obfuscation.SyntheticProject = false
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: desc},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	cred := oauthCred()
	cred.Meta.Project = ""
	if got := e.syntheticProjectFor(cred); got != "" {
		t.Fatalf("syntheticProjectFor = %q, want empty", got)
	}
}

// TestDeriveSessionIDFallbacks covers the credential-email and model fallbacks.
func TestDeriveSessionIDFallbacks(t *testing.T) {
	a := deriveSessionID(contracts.Credential{ID: "id"}, contracts.WireRequest{Model: "m"})
	b := deriveSessionID(contracts.Credential{Meta: contracts.AccountMeta{Email: "e@x"}}, contracts.WireRequest{Model: "m"})
	c := deriveSessionID(contracts.Credential{}, contracts.WireRequest{Model: "m"})
	if a == "" || b == "" || c == "" {
		t.Fatal("empty session id")
	}
	if a == b || b == c {
		t.Fatal("session ids collided across different seeds")
	}
}

// TestUncloakResponseBranches covers the empty-map and error paths.
func TestUncloakResponseBranches(t *testing.T) {
	e := &Executor{}
	if got := e.uncloakResponse([]byte("x"), nil); string(got) != "x" {
		t.Fatal("empty map should be identity")
	}
	if got := e.uncloakResponse(nil, map[string]string{"a_ide": "a"}); got != nil {
		t.Fatal("empty body should be identity")
	}
	// Malformed body: returned unchanged.
	bad := []byte("{")
	if got := e.uncloakResponse(bad, map[string]string{"a_ide": "a"}); string(got) != "{" {
		t.Fatal("malformed body should be identity")
	}
}

// TestIsImageModel covers the pattern.
func TestIsImageModel(t *testing.T) {
	if !isImageModel("gemini-3.1-flash-image") || !isImageModel("imagen-3") {
		t.Fatal("image model not detected")
	}
	if isImageModel("gemini-3.5-flash") {
		t.Fatal("text model misdetected as image")
	}
}

// --- DoStream paths ---

func TestDoStreamBuildError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "http://exa mple.test", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m", Stream: true}, oauthCred()); err == nil {
		t.Fatal("build error expected")
	}
}

func TestDoStreamTransportError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m", Stream: true}, oauthCred()); err == nil {
		t.Fatal("transport error expected")
	}
}

// TestDoStreamNonStreamBadJSON covers the non-stream branch's translate error.
func TestDoStreamNonStreamBadJSON(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{"))}, nil
		})))
	// Image model => non-stream path.
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"x-image","messages":[]}`), Model: "x-image", Stream: true}, oauthCred()); !hasCode(err, domain.CodeBadUpstreamResponse) {
		t.Fatalf("err = %v", err)
	}
}

// TestDoStreamNonStreamReadError covers the non-stream read failure.
func TestDoStreamNonStreamReadError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}, nil
		})))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"x-image","messages":[]}`), Model: "x-image", Stream: true}, oauthCred()); err == nil {
		t.Fatal("read error expected")
	}
}

// --- stream internals ---

func TestSSEStreamHeaders(t *testing.T) {
	s := &sseStream{headers: http.Header{"X": {"1"}}}
	if s.Headers().Get("X") != "1" {
		t.Fatal("headers not exposed")
	}
}

func TestSingleChunkStreamCloses(t *testing.T) {
	s := newSingleChunkStream(200, nil, nil)
	_ = s.Close()
	_ = s.Close()
	if s.closes != 2 {
		t.Fatalf("closes = %d", s.closes)
	}
}

func TestReadFrameSkipsCommentsAndNoise(t *testing.T) {
	raw := ": comment\n" + "event: message\n" + "data: {\"x\":1}\n\n" + "data: [DONE]\n\n"
	s := &sseStream{body: io.NopCloser(strings.NewReader(raw)), ctx: context.Background(), scanner: bufio.NewScanner(strings.NewReader(raw))}
	frame, ok, err := s.readFrame()
	if err != nil || !ok || string(frame) != `{"x":1}` {
		t.Fatalf("frame = %q, ok=%v, err=%v", frame, ok, err)
	}
	// After the payload the next read is [DONE] (skipped) then EOF.
	_, ok, err = s.readFrame()
	if err != nil || ok {
		t.Fatalf("expected clean EOF, ok=%v err=%v", ok, err)
	}
}

func TestReadFrameContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &sseStream{body: io.NopCloser(strings.NewReader("")), ctx: ctx, scanner: bufio.NewScanner(strings.NewReader(""))}
	if _, _, err := s.readFrame(); err == nil {
		t.Fatal("canceled context accepted")
	}
}

func TestReadErrorClosedByCaller(t *testing.T) {
	s := &sseStream{body: io.NopCloser(strings.NewReader(""))}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if !hasCode(s.readError(io.ErrUnexpectedEOF), domain.CodeUpstreamTimeout) {
		t.Fatalf("closed read error = %v", s.readError(io.ErrUnexpectedEOF))
	}
}

func TestBadFrameTyped(t *testing.T) {
	if !hasCode(badFrame(io.ErrUnexpectedEOF), domain.CodeBadUpstreamResponse) {
		t.Fatalf("badFrame = %v", badFrame(io.ErrUnexpectedEOF))
	}
}

// TestStreamRecvTranslatesAndUncloaks drives Recv through a full frame with tool
// cloaking.
func TestStreamRecvTranslatesAndUncloaks(t *testing.T) {
	raw := `data: {"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f_ide","args":{}}}]}}]}}` + "\n\n"
	s := &sseStream{
		body: io.NopCloser(strings.NewReader(raw)), ctx: context.Background(),
		scanner:    bufio.NewScanner(strings.NewReader(raw)),
		translator: translator(), model: "m",
		toolMap: map[string]string{"f_ide": "f"},
	}
	ch, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !strings.Contains(string(ch.Data), `"f"`) || strings.Contains(string(ch.Data), "f_ide") {
		t.Fatalf("chunk not uncloaked: %s", ch.Data)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v", err)
	}
}

// TestStreamRecvBadFrame covers Recv's translation error.
func TestStreamRecvBadFrame(t *testing.T) {
	raw := "data: {bad json\n\n"
	s := &sseStream{
		body: io.NopCloser(strings.NewReader(raw)), ctx: context.Background(),
		scanner: bufio.NewScanner(strings.NewReader(raw)), translator: translator(), model: "m",
	}
	if _, err := s.Recv(); !hasCode(err, domain.CodeBadUpstreamResponse) {
		t.Fatalf("err = %v", err)
	}
}

// TestStreamRecvNoiseThenEOF covers the empty-translation skip.
func TestStreamRecvNoiseThenEOF(t *testing.T) {
	raw := `data: {"response":{}}` + "\n\n"
	s := &sseStream{
		body: io.NopCloser(strings.NewReader(raw)), ctx: context.Background(),
		scanner: bufio.NewScanner(strings.NewReader(raw)), translator: translator(), model: "m",
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("noise frame should skip to EOF, got %v", err)
	}
}

// --- uncloak internals ---

func TestUncloakToolNamesMessageShape(t *testing.T) {
	body := `{"choices":[{"index":0,"message":{"tool_calls":[{"function":{"name":"a_ide"}}]}}]}`
	out, err := uncloakToolNames([]byte(body), map[string]string{"a_ide": "a"})
	if err != nil || !strings.Contains(string(out), `"name":"a"`) {
		t.Fatalf("message shape not uncloaked: %s, %v", out, err)
	}
}

func TestUncloakToolNamesNoChoices(t *testing.T) {
	in := []byte(`{"model":"m"}`)
	out, err := uncloakToolNames(in, map[string]string{"a_ide": "a"})
	if err != nil || string(out) != string(in) {
		t.Fatalf("no-choices = %s, %v", out, err)
	}
}

func TestUncloakToolNamesBadChoices(t *testing.T) {
	in := []byte(`{"choices":"nope"}`)
	if _, err := uncloakToolNames(in, map[string]string{"a_ide": "a"}); err == nil {
		t.Fatal("bad choices accepted")
	}
}

func TestUncloakFunctionNoFunction(t *testing.T) {
	call := map[string]json.RawMessage{}
	if uncloakFunction(call, map[string]string{"a_ide": "a"}) {
		t.Fatal("no function should not change")
	}
}

func TestUncloakFunctionBadName(t *testing.T) {
	call := map[string]json.RawMessage{"function": json.RawMessage(`{"name":123}`)}
	if uncloakFunction(call, map[string]string{"a_ide": "a"}) {
		t.Fatal("bad name should not change")
	}
}

// --- real streaming via httptest for the non-stream DoStream branch ---

func TestDoStreamImageViaRealServer(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"response":{"candidates":[{"content":{"parts":[{"text":"i"}]}}]}}`))
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 0)
	s, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"x-image","messages":[]}`), Model: "x-image", Stream: true}, oauthCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer s.Close()
	if _, err := s.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits = %d", hits)
	}
}

// translator returns the Gemini translator the executor uses.
func translator() contracts.Translator { return translators.GeminiToOpenAI{} }

// TestDoNonStreamTranslateError covers Do's ResponseFull error (bad wrapper).
func TestDoNonStreamTranslateError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"response":"not an object"}`))}, nil
		})))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred()); !hasCode(err, domain.CodeBadUpstreamResponse) {
		t.Fatalf("err = %v", err)
	}
}

// TestBuildEnvelopeBadCanonical covers the translate error in buildEnvelope.
func TestBuildEnvelopeBadCanonical(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.buildEnvelope(contracts.WireRequest{Body: []byte(`{`), Model: "m"}, oauthCred(), false); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

// TestStreamUncloakErrorPath covers uncloak's error fallback: a malformed chunk
// with a non-empty map returns the chunk unchanged.
func TestStreamUncloakErrorPath(t *testing.T) {
	s := &sseStream{toolMap: map[string]string{"a_ide": "a"}}
	if got := s.uncloak([]byte("{")); string(got) != "{" {
		t.Fatalf("malformed uncloak = %s", got)
	}
	if got := s.uncloak([]byte(`{"choices":[]}`)); string(got) != `{"choices":[]}` {
		t.Fatalf("no-op uncloak = %s", got)
	}
}

// TestReadErrorIdleFired covers the idleFired branch.
func TestReadErrorIdleFired(t *testing.T) {
	s := &sseStream{body: io.NopCloser(strings.NewReader(""))}
	s.mu.Lock()
	s.idleFired = true
	s.mu.Unlock()
	if !hasCode(s.readError(io.ErrUnexpectedEOF), domain.CodeUpstreamTimeout) {
		t.Fatal("idleFired branch wrong")
	}
}

// TestUncloakSkipsNonObjectChoice covers the message-unmarshal-failure and
// missing-tool_calls branches.
func TestUncloakSkipsNonObjectChoice(t *testing.T) {
	// message is not an object -> skip.
	in := `{"choices":[{"message":"notobj"}]}`
	if out, err := uncloakToolNames([]byte(in), map[string]string{"a_ide": "a"}); err != nil || string(out) != in {
		t.Fatalf("non-object message = %s, %v", out, err)
	}
	// delta has no tool_calls -> skip.
	in2 := `{"choices":[{"delta":{"content":"x"}}]}`
	if out, err := uncloakToolNames([]byte(in2), map[string]string{"a_ide": "a"}); err != nil || string(out) != in2 {
		t.Fatalf("no tool_calls = %s, %v", out, err)
	}
	// tool_calls not an array -> skip.
	in3 := `{"choices":[{"delta":{"tool_calls":"nope"}}]}`
	if out, err := uncloakToolNames([]byte(in3), map[string]string{"a_ide": "a"}); err != nil || string(out) != in3 {
		t.Fatalf("bad tool_calls = %s, %v", out, err)
	}
}

// TestUncloakFunctionBadFunction covers the function-unmarshal failure.
func TestUncloakFunctionBadFunction(t *testing.T) {
	call := map[string]json.RawMessage{"function": json.RawMessage(`"notobj"`)}
	if uncloakFunction(call, map[string]string{"a_ide": "a"}) {
		t.Fatal("bad function should not change")
	}
}

// TestLooksLikeRequestIDEmptyTrajectory covers the empty-trajectory branch.
func TestLooksLikeRequestIDEmptyTrajectory(t *testing.T) {
	if looksLikeRequestID("agent/c/1//1") {
		t.Fatal("empty trajectory accepted")
	}
}

// TestBuildRequestIDZeroTimestamp covers the ts==0 fallback.
func TestBuildRequestIDZeroTimestamp(t *testing.T) {
	// A body whose hash bytes 0..5 are zero is impractical; instead assert the
	// shape holds for a normal request (the ts fallback is defensive).
	id := buildRequestID(antigravityDescriptor(), oauthCred(),
		contracts.WireRequest{Body: []byte(`{"model":"m","messages":[{"role":"user"}]}`), Model: "m"}, "s", time.Unix(0, 7))
	if !looksLikeRequestID(id) {
		t.Fatalf("id = %q", id)
	}
}

// TestContentCountMessageArray covers the array branch used by request ids.
func TestContentCountMessageArray(t *testing.T) {
	if got := contentCount([]byte(`{"messages":[{"role":"user"},{"role":"assistant"},{"role":"user"}]}`)); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}

// TestMarshalSeamErrorBranches injects a failing marshal to reach the defensive
// error branches in cleanRequest and uncloakToolNames.
func TestMarshalSeamErrorBranches(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { jsonMarshal = orig }()

	if _, err := cleanRequest([]byte(`{"x":1}`), false, "s"); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("cleanRequest err = %v", err)
	}
	if _, err := uncloakToolNames([]byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"a_ide"}}]}}]}`), map[string]string{"a_ide": "a"}); err == nil {
		t.Fatal("uncloakToolNames should error")
	}
}

// TestDoNon2xxShortCircuit covers Do's post-error status check on a 2xx body read
// (the path is reached through post, so exercise post's non-2xx branch directly).
func TestPostNon2xx(t *testing.T) {
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 502, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("boom"))}, nil
		})))
	env, _ := e.buildEnvelope(contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred(), false)
	if _, err := e.post(context.Background(), "https://x", env, oauthCred()); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("post err = %v", err)
	}
}

// TestRecvTerminalAfterRecord covers Recv returning the stored terminal outcome.
func TestRecvTerminalAfterRecord(t *testing.T) {
	raw := ""
	s := &sseStream{body: io.NopCloser(strings.NewReader(raw)), ctx: context.Background(),
		scanner: bufio.NewScanner(strings.NewReader(raw))}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("first = %v", err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("terminal = %v", err)
	}
}

// TestRecvContextCanceled covers Recv's ctx-cancel branch.
func TestRecvContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &sseStream{body: io.NopCloser(strings.NewReader("")), ctx: ctx, scanner: bufio.NewScanner(strings.NewReader(""))}
	if !hasCode(s.mustRecvErr(), domain.CodeUpstreamTimeout) {
		t.Fatal("canceled ctx not mapped")
	}
}

// mustRecvErr runs Recv and returns its error as a DomainError.
func (s *sseStream) mustRecvErr() *domain.DomainError {
	_, err := s.Recv()
	de, _ := err.(*domain.DomainError)
	return de
}

// TestLooksLikeRequestIDNumericEmpty covers the empty numeric-ts branch.
func TestLooksLikeRequestIDNumericEmpty(t *testing.T) {
	if looksLikeRequestID("agent/c//t/1") {
		t.Fatal("empty ts accepted")
	}
}

// TestUncloakFunctionNameUnknown covers the no-change branch (name maps to itself).
func TestUncloakFunctionNameUnknown(t *testing.T) {
	call := map[string]json.RawMessage{"function": json.RawMessage(`{"name":"untouched"}`)}
	if uncloakFunction(call, map[string]string{"a_ide": "a"}) {
		t.Fatal("unknown name changed")
	}
}

// TestUncloakNoChangeReturnsInput covers the !changed early return.
func TestUncloakNoChangeReturnsInput(t *testing.T) {
	in := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"untouched"}}]}}]}`
	out, err := uncloakToolNames([]byte(in), map[string]string{"a_ide": "a"})
	if err != nil || string(out) != in {
		t.Fatalf("no-change = %s, %v", out, err)
	}
}

// TestNewRequestMarshalError covers newRequest's marshal failure via the seam.
func TestNewRequestMarshalError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { jsonMarshal = orig }()

	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	env := envelope{Project: "p", Model: "m", UserAgent: "u", RequestID: "r", Request: json.RawMessage(`{}`)}
	if _, err := e.newRequest(context.Background(), "https://x", env, oauthCred()); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("newRequest marshal err = %v", err)
	}
}

// TestBuildEnvelopeCloakError covers CloakTools' invalid-JSON branch: a
// descriptor with tool cloaking but no prompt rewrites passes invalid JSON
// straight to CloakTools.
func TestBuildEnvelopeCloakError(t *testing.T) {
	desc := antigravityDescriptor()
	desc.Obfuscation.PromptRewrites = nil // Apply becomes a pure copy
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: desc},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.buildEnvelope(contracts.WireRequest{Body: []byte(`{`), Model: "m"}, oauthCred(), false); err == nil {
		t.Fatal("expected the CloakTools error")
	}
}

// TestDoStreamEnvelopeError covers DoStream's buildEnvelope failure.
func TestDoStreamEnvelopeError(t *testing.T) {
	desc := antigravityDescriptor()
	desc.Obfuscation.PromptRewrites = nil
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: desc},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{`), Model: "m", Stream: true}, oauthCred()); err == nil {
		t.Fatal("expected DoStream envelope error")
	}
}

// TestDoEnvelopeError covers Do's buildEnvelope failure.
func TestDoEnvelopeError(t *testing.T) {
	desc := antigravityDescriptor()
	desc.Obfuscation.PromptRewrites = nil
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: desc},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{`), Model: "m"}, oauthCred()); err == nil {
		t.Fatal("expected Do envelope error")
	}
}

// TestUncloakChoicesMarshalError covers the choices re-marshal failure.
func TestUncloakChoicesMarshalError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { jsonMarshal = orig }()
	in := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"a_ide"}}]}}]}`
	if _, err := uncloakToolNames([]byte(in), map[string]string{"a_ide": "a"}); err == nil {
		t.Fatal("expected choices marshal error")
	}
}

// TestUncloakFunctionNoName covers the missing-name branch.
func TestUncloakFunctionNoName(t *testing.T) {
	call := map[string]json.RawMessage{"function": json.RawMessage(`{}`)}
	if uncloakFunction(call, map[string]string{"a_ide": "a"}) {
		t.Fatal("missing name should not change")
	}
}

// TestBuildEnvelopeTranslateError covers the translator.Request error branch: a
// descriptor with no obfuscation passes a valid-but-wrong-shape canonical body
// straight to the Gemini translator, which rejects it.
func TestBuildEnvelopeTranslateError(t *testing.T) {
	desc := contracts.ProviderDescriptor{ID: "antigravity", Protocol: contracts.WireCloudCode}
	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: desc},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.buildEnvelope(contracts.WireRequest{Body: []byte(`[1,2]`), Model: "m"}, oauthCred(), false); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

// TestBuildEnvelopeCleanError covers buildEnvelope's cleanRequest error via the
// marshal seam.
func TestBuildEnvelopeCleanError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { jsonMarshal = orig }()

	e := mustExecutor(t, Config{Family: "a", BaseURL: "https://x", Descriptor: antigravityDescriptor()},
		testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })))
	if _, err := e.buildEnvelope(contracts.WireRequest{Body: []byte(`{"model":"m","messages":[]}`), Model: "m"}, oauthCred(), false); err == nil {
		t.Fatal("expected cleanRequest error")
	}
}

// TestReadErrorPeerDeath covers readError's fall-through (neither idle nor
// closed): a reader that fails on its own.
func TestReadErrorPeerDeath(t *testing.T) {
	s := &sseStream{body: peerErrBody{}, ctx: context.Background(), scanner: bufio.NewScanner(peerErrBody{})}
	if !hasCode(s.readError(io.ErrUnexpectedEOF), domain.CodeUpstreamUnavailable) {
		t.Fatal("peer death not mapped to upstream_unavailable")
	}
}

type peerErrBody struct{}

func (peerErrBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (peerErrBody) Close() error             { return nil }

// TestUncloakRootMarshalError covers the second (root) marshal failure in
// uncloakToolNames by failing only that call.
func TestUncloakRootMarshalError(t *testing.T) {
	orig := jsonMarshal
	calls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		calls++
		if calls >= 2 {
			return nil, io.ErrUnexpectedEOF
		}
		return orig(v)
	}
	defer func() { jsonMarshal = orig }()
	in := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"a_ide"}}]}}]}`
	if _, err := uncloakToolNames([]byte(in), map[string]string{"a_ide": "a"}); err == nil {
		t.Fatal("expected root marshal error")
	}
}
