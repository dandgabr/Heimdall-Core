package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// fakeResolver returns a scripted plan/error.
type fakeResolver struct {
	plan   contracts.RoutePlan
	err    error
	combo  domain.ComboID
	req    *contracts.Request
	called bool
}

func (r *fakeResolver) Resolve(_ context.Context, req *contracts.Request, combo domain.ComboID) (contracts.RoutePlan, error) {
	r.called = true
	r.req = req
	r.combo = combo
	return r.plan, r.err
}

// fakeDispatcher returns scripted results.
type fakeDispatcher struct {
	resp     *contracts.Response
	err      error
	stream   contracts.Stream
	stErr    error
	doCalls  int
	stCalls  int
	gotWire  contracts.WireRequest
	gotPlan  contracts.RoutePlan
	lastPlan contracts.RoutePlan
}

func (d *fakeDispatcher) Do(_ context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (*contracts.Response, error) {
	d.doCalls++
	d.gotWire = req
	d.gotPlan = plan
	return d.resp, d.err
}

func (d *fakeDispatcher) DoStream(_ context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (contracts.Stream, error) {
	d.stCalls++
	d.gotWire = req
	d.lastPlan = plan
	return d.stream, d.stErr
}

// fakeComboLoader resolves combos from a map.
type fakeComboLoader struct {
	combos map[domain.ComboID]combos.Combo
}

func (l *fakeComboLoader) Get(_ context.Context, id domain.ComboID) (combos.Combo, error) {
	c, ok := l.combos[id]
	if !ok {
		return combos.Combo{}, combos.ErrNotFound
	}
	return c, nil
}

// fakeChain is a scriptable GateChain.
type fakeChain struct {
	pre      contracts.Decision
	preErr   error
	chunkDec contracts.ChunkDecision
	chunkErr error
	postErr  error
	preCalls int
	postCall int
	// chunkSawDerived records the Derived the chain saw in the chunk stage.
	chunkSawDerived *contracts.Derived
	// needsBody scripts ConsumesRequestBody; preBody records what PreRequest saw.
	needsBody bool
	preBody   []byte
	// preMeta records the Meta the chain saw, so boundary-propagation tests
	// (the client key, G-1) can assert what the gates would read.
	preMeta map[string]string
}

func (c *fakeChain) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	c.preCalls++
	c.preBody = in.Body
	c.preMeta = in.Meta
	return c.pre, c.preErr
}
func (c *fakeChain) OnResponseChunk(_ context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	c.chunkSawDerived = in.Derived
	return c.chunkDec, c.chunkErr
}

// TestChatReusesDerivedFromDecision proves the gateway threads the chain's
// request-scoped Derived into the chunk stage (ADR-0014 §6).
func TestChatReusesDerivedFromDecision(t *testing.T) {
	dv := &contracts.Derived{RequestID: "r"}
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}
	chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue, Derived: dv}}
	h := newHandler(res, disp, nil, chain)
	serve(h, `{"model":"m","stream":true,"messages":[]}`)
	if chain.chunkSawDerived != dv {
		t.Fatalf("chunk stage did not receive the decision's Derived: %+v", chain.chunkSawDerived)
	}
}
func (c *fakeChain) PostResponse(context.Context, contracts.GateInput) error {
	c.postCall++
	return c.postErr
}

// ConsumesRequestBody reports the scripted body need.
func (c *fakeChain) ConsumesRequestBody() bool { return c.needsBody }

// sawBody records the body the chain received, to assert body delivery.
func (c *fakeChain) PreRequestBody() []byte { return c.preBody }

// memStream is an in-memory contracts.Stream.
type memStream struct {
	chunks []contracts.Chunk
	err    error
	i      int
}

func (s *memStream) Headers() http.Header { return http.Header{} }
func (s *memStream) Recv() (contracts.Chunk, error) {
	if s.i < len(s.chunks) {
		ch := s.chunks[s.i]
		s.i++
		return ch, nil
	}
	if s.err != nil {
		return contracts.Chunk{}, s.err
	}
	return contracts.Chunk{}, io.EOF
}
func (s *memStream) Close() error { return nil }

func newHandler(res Resolver, disp Dispatcher, loader ComboLoader, chain Chain) *Handler {
	return New(res, disp, loader, chain, i18n.MustNew(), nil)
}

func serve(h *Handler, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func samplePlan() contracts.RoutePlan {
	return contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "p", Model: "m"}}, MaxRounds: 1}
}

func TestChatNonStream(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{
		Candidate: contracts.Candidate{Provider: "p", Model: "m"},
		Wire:      contracts.WireResponse{Status: 200, Body: []byte(`{"id":"x","choices":[]}`)},
		Attempts:  1,
	}}
	chain := &fakeChain{}
	h := newHandler(res, disp, nil, chain)

	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"x"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if chain.preCalls != 1 || chain.postCall != 1 {
		t.Fatalf("chain pre=%d post=%d, want both once", chain.preCalls, chain.postCall)
	}
}

// TestChatComboResolution proves a combo id in the model field is resolved as a
// combo (not a raw model).
func TestChatComboResolution(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{
		"fast": combos.NewCombo("fast", contracts.StrategyFallback, []combos.Step{{Kind: combos.StepModel, Ref: "m"}}),
	}}
	h := newHandler(res, disp, loader, nil)

	rec := serve(h, `{"model":"fast","messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if res.combo != "fast" {
		t.Fatalf("resolved combo = %q, want fast", res.combo)
	}
	if res.req.Model != "" {
		t.Fatalf("model = %q, want empty for a combo target", res.req.Model)
	}
}

func TestChatBadBody(t *testing.T) {
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, nil)
	for _, body := range []string{`{bad`, `{}`} {
		rec := serve(h, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestChatGateBlockSynthetic(t *testing.T) {
	chain := &fakeChain{pre: contracts.Decision{
		Kind: contracts.DecisionBlock,
		Synthetic: &contracts.SyntheticResponse{
			Status:  http.StatusTeapot,
			Body:    []byte(`{"cached":true}`),
			Headers: http.Header{"X-Cache": []string{"hit"}},
		},
	}}
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, chain)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the synthetic status", rec.Code)
	}
	if rec.Header().Get("X-Cache") != "hit" {
		t.Fatalf("cache header missing")
	}
	if !strings.Contains(rec.Body.String(), "cached") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestChatGateBlockMissingSynthetic(t *testing.T) {
	chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionBlock}}
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, chain)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestChatGateRerouteRefused(t *testing.T) {
	chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionReroute}}
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, chain)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestChatGateModifyRewritesBody(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
	chain := &fakeChain{pre: contracts.Decision{
		Kind: contracts.DecisionModify,
		Body: []byte(`{"model":"rewritten","messages":[]}`),
	}}
	h := newHandler(res, disp, nil, chain)
	serve(h, `{"model":"m","messages":[]}`)
	if string(disp.gotWire.Body) != `{"model":"rewritten","messages":[]}` {
		t.Fatalf("wire body = %s, want the modified body", disp.gotWire.Body)
	}
}

// TestChatGateModifyHeaders proves a header-only Modify reaches the dispatcher's
// WireRequest.
func TestChatGateModifyHeaders(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
	chain := &fakeChain{pre: contracts.Decision{
		Kind:    contracts.DecisionModify,
		Headers: map[string][]string{"X-New": {"v"}},
	}}
	h := newHandler(res, disp, nil, chain)
	serve(h, `{"model":"m","messages":[]}`)
	if got := disp.gotWire.Headers.Get("X-New"); got != "v" {
		t.Fatalf("modified header not applied: %q", got)
	}
}

func TestChatGatePreRequestError(t *testing.T) {
	chain := &fakeChain{preErr: errors.New("pre boom")}
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, chain)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestChatResolverError(t *testing.T) {
	res := &fakeResolver{err: domain.New(domain.CodeRouteNoCandidate, domain.WithHTTPStatus(400), domain.WithScope(domain.ScopeRequest))}
	h := newHandler(res, &fakeDispatcher{}, nil, nil)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestChatDispatcherError(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{err: domain.New(domain.CodeDispatchExhausted, domain.WithHTTPStatus(502))}
	chain := &fakeChain{}
	h := newHandler(res, disp, nil, chain)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
	if chain.postCall != 1 {
		t.Fatal("PostResponse did not run on the error path")
	}
}

// TestStreamRelay proves the SSE framing and the [DONE] sentinel.
func TestStreamRelay(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{
		{Event: "custom", Data: []byte(`{"choices":[]}`), ID: "1"},
		{Data: []byte(`{"choices":[]}`)},
	}}}
	chain := &fakeChain{}
	h := newHandler(res, disp, nil, chain)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: custom") {
		t.Fatalf("named event not forwarded: %s", body)
	}
	if !strings.Contains(body, "id: 1") {
		t.Fatalf("event id not forwarded: %s", body)
	}
	if !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("done sentinel missing: %s", body)
	}
	if chain.postCall != 1 {
		t.Fatal("PostResponse did not run for a stream")
	}
}

// TestStreamPostCommitErrorIsSSEEvent proves a mid-stream error becomes a
// terminal SSE frame, never an HTTP status change.
func TestStreamPostCommitErrorIsSSEEvent(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{
		chunks: []contracts.Chunk{{Data: []byte("partial")}},
		err:    domain.New(domain.CodeUpstreamUnavailable, domain.WithHTTPStatus(502)),
	}}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (committed)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: error") {
		t.Fatalf("terminal SSE error missing: %s", body)
	}
	if !strings.Contains(body, "upstream") && !strings.Contains(body, "error") {
		t.Fatalf("error code missing: %s", body)
	}
}

// TestStreamDispatcherPreCommitError proves a pre-commit stream error is a real
// HTTP error.
func TestStreamDispatcherPreCommitError(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stErr: domain.New(domain.CodeUpstreamUnavailable, domain.WithHTTPStatus(502))}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

// TestStreamChunkDropAndReplace proves the per-chunk gate decisions.
func TestStreamChunkDropAndReplace(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{
		{Data: []byte("drop-me")},
		{Data: []byte("replace-me")},
	}}}
	// First chunk dropped; subsequent chunks replaced.
	calls := 0
	chain := &replaceThenDropChain{fn: func() contracts.ChunkDecision {
		calls++
		if calls == 1 {
			return contracts.ChunkDecision{Kind: contracts.ChunkDrop}
		}
		return contracts.ChunkDecision{Kind: contracts.ChunkReplace, Body: []byte("REPLACED")}
	}}
	h := newHandler(res, disp, nil, chain)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)
	body := rec.Body.String()
	if strings.Contains(body, "drop-me") {
		t.Fatalf("dropped chunk leaked: %s", body)
	}
	if !strings.Contains(body, "REPLACED") {
		t.Fatalf("replaced chunk missing: %s", body)
	}
}

// replaceThenDropChain is a chain whose chunk decision is driven by a function.
type replaceThenDropChain struct {
	fn func() contracts.ChunkDecision
}

func (c *replaceThenDropChain) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (c *replaceThenDropChain) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return c.fn(), nil
}
func (c *replaceThenDropChain) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (c *replaceThenDropChain) ConsumesRequestBody() bool                               { return false }

// TestStreamChunkGateErrorIsSSE proves a FailClosed chunk-gate error becomes a
// terminal SSE event.
func TestStreamChunkGateErrorIsSSE(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}
	chain := &fakeChain{chunkErr: domain.New(domain.CodeInternal, domain.WithHTTPStatus(500))}
	h := newHandler(res, disp, nil, chain)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)
	if !strings.Contains(rec.Body.String(), "event: error") {
		t.Fatalf("chunk-gate error not surfaced as SSE: %s", rec.Body.String())
	}
}

// TestWriteSyntheticDefaultStatus covers the zero-status default.
func TestWriteSyntheticDefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSynthetic(rec, &contracts.SyntheticResponse{Body: []byte(`{}`)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
}

// TestAsDomainNonDomain covers the non-domain normalisation.
func TestAsDomainNonDomain(t *testing.T) {
	de := asDomain(errors.New("boom"))
	if de.Code != domain.CodeInternal {
		t.Fatalf("asDomain = %+v", de)
	}
}

// TestParseInvalid covers the JSON parse error branch directly.
func TestParseInvalid(t *testing.T) {
	if _, err := parse([]byte("{bad")); err == nil {
		t.Fatal("parse accepted invalid JSON")
	}
}

// TestHeaderNamesOnlyNoValues proves the gate input never carries a header value.
func TestHeaderNamesOnlyNoValues(t *testing.T) {
	src := http.Header{"Authorization": []string{"Bearer secret"}}
	got := headerNamesOnly(src)
	if _, ok := got["Authorization"]; !ok {
		t.Fatal("header name dropped")
	}
	if len(got["Authorization"]) != 0 {
		t.Fatalf("header value leaked: %v", got["Authorization"])
	}
}

// TestChatNoChain proves the handler works with a nil chain.
func TestChatNoChain(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestStreamExactlyOneDone is the D-01 regression at the gateway: an upstream
// whose decoder already consumed `[DONE]` yields a data chunk then EOF, and the
// gateway emits EXACTLY ONE `data: [DONE]` and no chunk whose data is `[DONE]`.
func TestStreamExactlyOneDone(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	// The stream delivers real data only; the `[DONE]` was consumed by the
	// decoder and became the EOF below.
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{
		{Data: []byte(`{"choices":[{"delta":{"content":"hi"}}]}`)},
	}}}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)

	body := rec.Body.String()
	if n := strings.Count(body, "data: [DONE]"); n != 1 {
		t.Fatalf("data: [DONE] count = %d, want exactly 1; body:\n%s", n, body)
	}
	// No relayed chunk carries `[DONE]` as its data.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "[DONE]") && line != "data: [DONE]" {
			t.Fatalf("a chunk leaked [DONE] in its data: %q", line)
		}
	}
}

// TestStreamDefenseInDepthSuppressesDuplicateDone proves the gateway's defence
// in depth: if a chunk ever contains `[DONE]` as data (a gate Replace, a legacy
// Stream), the gateway does not append a SECOND sentinel at EOF.
func TestStreamDefenseInDepthSuppressesDuplicateDone(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	// A hostile/legacy stream delivers `[DONE]` as a chunk.
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{
		{Data: []byte(`{"choices":[]}`)},
		{Data: []byte("[DONE]")},
	}}}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)

	body := rec.Body.String()
	// Exactly one sentinel total: the relayed one, with no duplicate at EOF.
	if n := strings.Count(body, "[DONE]"); n != 1 {
		t.Fatalf("[DONE] occurrences = %d, want exactly 1; body:\n%s", n, body)
	}
}

// TestStreamNoUpstreamDoneStillEmitsOne proves the gateway emits its own
// `[DONE]` when the upstream sent none.
func TestStreamNoUpstreamDoneStillEmitsOne(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{
		{Data: []byte(`{"choices":[]}`)},
	}}}
	h := newHandler(res, disp, nil, nil)
	rec := serve(h, `{"model":"m","stream":true,"messages":[]}`)

	body := rec.Body.String()
	if n := strings.Count(body, "data: [DONE]"); n != 1 {
		t.Fatalf("data: [DONE] count = %d, want 1; body:\n%s", n, body)
	}
}

// TestWriteErrorEnvelope proves the error writer's shape.
func TestWriteErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	writeError(rec, req, domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(400), domain.WithParams(map[string]string{"reason": "r"})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	var env map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if env["error"]["code"] != domain.CodeInvalidRequest {
		t.Fatalf("code = %v", env["error"]["code"])
	}
}

// TestWriteErrorDefaultStatus covers the zero-status default in writeError.
func TestWriteErrorDefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	writeError(rec, req, domain.New(domain.CodeInternal))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// errReader always fails on Read, so the read-error branch is reached.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

// TestChatReadError covers the body-read failure branch.
func TestChatReadError(t *testing.T) {
	mux := http.NewServeMux()
	newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, nil).Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", errReader{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestChatBodyTooLarge covers the size guard.
func TestChatBodyTooLarge(t *testing.T) {
	big := strings.Repeat("a", MaxRequestBytes+1)
	rec := serve(newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, nil), big)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestChatZeroWireStatusDefaults200 covers the zero-status default on success.
func TestChatZeroWireStatusDefaults200(t *testing.T) {
	res := &fakeResolver{plan: samplePlan()}
	disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Body: []byte(`{}`)}}}
	rec := serve(newHandler(res, disp, nil, nil), `{"model":"m","messages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestResolveTargetNilLoader covers the nil-combo-loader default.
func TestResolveTargetNilLoader(t *testing.T) {
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, nil, nil)
	combo, model := h.resolveTarget(context.Background(), "m")
	if combo != "" || model != "m" {
		t.Fatalf("resolveTarget = %q / %q, want empty / m", combo, model)
	}
}

// nonFlusherWriter wraps a ResponseWriter without exposing Flusher, so the
// writeSSE* no-flusher branches are covered.
type nonFlusherWriter struct{ h http.Header }

func (w *nonFlusherWriter) Header() http.Header         { return w.h }
func (w *nonFlusherWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nonFlusherWriter) WriteHeader(int)             {}

// TestWriteSSEChunkNoFlusher covers the nil-flusher guards.
func TestWriteSSEChunkNoFlusher(t *testing.T) {
	w := &nonFlusherWriter{h: http.Header{}}
	writeSSEChunk(w, nil, contracts.Chunk{Event: "custom", ID: "7", Data: []byte("d")})
	writeSSEDone(w, nil)
	writeSSEError(w, nil, domain.New(domain.CodeUpstreamUnavailable, domain.WithHTTPStatus(502)))
}

// TestWriteErrorRedactsParams covers writeError's param redaction path.
func TestWriteErrorRedactsParams(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	writeError(rec, req, domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(400),
		domain.WithParams(map[string]string{"reason": "Authorization: Bearer sk-secret-value-123456"})))
	if strings.Contains(rec.Body.String(), "sk-secret-value") {
		t.Fatalf("secret leaked: %s", rec.Body.String())
	}
}

// TestWriteErrorZeroStatus covers the zero-HTTPStatus default.
func TestWriteErrorZeroStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	// domain.New defaults HTTPStatus to 500, so build one and clear it.
	de := domain.New(domain.CodeInternal)
	de.HTTPStatus = 0
	writeError(rec, req, de)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestResolveTargetNonCombo covers the loader-present, model-not-a-combo path.
func TestResolveTargetNonCombo(t *testing.T) {
	loader := &fakeComboLoader{combos: map[domain.ComboID]combos.Combo{}}
	h := newHandler(&fakeResolver{}, &fakeDispatcher{}, loader, nil)
	combo, model := h.resolveTarget(context.Background(), "plain-model")
	if combo != "" || model != "plain-model" {
		t.Fatalf("resolveTarget = %q / %q, want empty / plain-model", combo, model)
	}
}

// TestChatDeliversBodyOnlyWhenDeclared is the SEC-03 §2 regression at the HTTP
// boundary: the body reaches PreRequest ONLY when the chain declares it needs it.
func TestChatDeliversBodyOnlyWhenDeclared(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	t.Run("declared need", func(t *testing.T) {
		res := &fakeResolver{plan: samplePlan()}
		disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
		chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue}, needsBody: true}
		h := newHandler(res, disp, nil, chain)
		rec := serve(h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if string(chain.PreRequestBody()) != body {
			t.Fatalf("body not delivered: %q", chain.PreRequestBody())
		}
	})

	t.Run("not declared", func(t *testing.T) {
		res := &fakeResolver{plan: samplePlan()}
		disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
		chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue}, needsBody: false}
		h := newHandler(res, disp, nil, chain)
		serve(h, body)
		if chain.PreRequestBody() != nil {
			t.Fatalf("body delivered without a declaration: %q", chain.PreRequestBody())
		}
	})

	t.Run("nil chain", func(t *testing.T) {
		res := &fakeResolver{plan: samplePlan()}
		disp := &fakeDispatcher{resp: &contracts.Response{Wire: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}
		h := newHandler(res, disp, nil, nil)
		if rec := serve(h, body); rec.Code != http.StatusOK {
			t.Fatalf("nil chain status = %d", rec.Code)
		}
	})
}

// TestNewDefaultsIDs covers the nil IDGen default.
func TestNewDefaultsIDs(t *testing.T) {
	h := New(&fakeResolver{}, &fakeDispatcher{}, nil, nil, i18n.MustNew(), nil)
	if h.ids == nil {
		t.Fatal("ids not defaulted")
	}
	if (domainIDGen{}).NewRequestID() == "" {
		t.Fatal("NewRequestID empty")
	}
}
