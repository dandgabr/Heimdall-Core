package dispatcher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// panelExecutor returns a per-call response body built from the request's last
// user message, so a test can prove the judge/next-step receives the previous
// output. It records every request body.
type panelExecutor struct {
	family domain.ProviderID
	mu     sync.Mutex
	reqs   []string
	// fn builds the response body from the request body.
	fn func(body string) string
	// fail panics? no: fail marks a call as failing.
	fail func(body string) bool
}

func (e *panelExecutor) Family() domain.ProviderID { return e.family }
func (e *panelExecutor) Do(_ context.Context, req contracts.WireRequest, _ contracts.Credential) (contracts.WireResponse, error) {
	e.mu.Lock()
	e.reqs = append(e.reqs, string(req.Body))
	e.mu.Unlock()
	if e.fail != nil && e.fail(string(req.Body)) {
		return contracts.WireResponse{}, domain.New(domain.CodeUpstreamUnavailable,
			domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))
	}
	return contracts.WireResponse{Status: 200, Body: []byte(e.fn(string(req.Body)))}, nil
}
func (e *panelExecutor) DoStream(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	resp, err := e.Do(ctx, req, cred)
	if err != nil {
		return nil, err
	}
	return &memStream{chunks: []contracts.Chunk{{Data: resp.Body}}}, nil
}
func (e *panelExecutor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

// perProviderFactory returns a distinct executor per provider, all sharing one
// recorder of requests via the provider's executor.
type perProviderFactory struct {
	execs map[domain.ProviderID]*panelExecutor
}

func (f *perProviderFactory) Build(_ context.Context, c contracts.Candidate, _ contracts.Credential) (contracts.Executor, error) {
	if ex, ok := f.execs[c.Provider]; ok {
		return ex, nil
	}
	return nil, domain.New(domain.CodeProviderNotFound, domain.WithHTTPStatus(404))
}

// contentBody builds a canonical response whose assistant content is `content`.
func contentBody(content string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": content}}},
	})
	return string(b)
}

// lastUserContent reads the last message's content from a canonical request.
func lastUserContent(t *testing.T, body string) string {
	t.Helper()
	var payload struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode request %q: %v", body, err)
	}
	if len(payload.Messages) == 0 {
		return ""
	}
	return payload.Messages[len(payload.Messages)-1].Content
}

func baseReq() contracts.WireRequest {
	return contracts.WireRequest{
		Body:  []byte(`{"model":"m","messages":[{"role":"user","content":"original"}]}`),
		Model: "m",
	}
}

// credsFor builds a credential source for the given providers.
func credsFor(providers ...string) *fakeCreds {
	byID := map[domain.CredentialID]contracts.Credential{}
	byProv := map[domain.ProviderID][]domain.CredentialID{}
	for _, p := range providers {
		id := domain.CredentialID("cred-" + p)
		byID[id] = contracts.Credential{ID: id, Provider: domain.ProviderID(p)}
		byProv[domain.ProviderID(p)] = []domain.CredentialID{id}
	}
	return &fakeCreds{byProvider: byProv, byID: byID}
}

// TestFusionRunsPanelsThenJudge proves the fan-out runs every panel and the
// judge receives their ANONYMISED outputs, with the judge's response winning.
func TestFusionRunsPanelsThenJudge(t *testing.T) {
	// Panels answer "p1"/"p2"; the judge echoes the digest it received.
	panel1 := &panelExecutor{family: "a", fn: func(string) string { return contentBody("answer-a") }}
	panel2 := &panelExecutor{family: "b", fn: func(string) string { return contentBody("answer-b") }}
	judge := &panelExecutor{family: "j", fn: func(body string) string {
		// The judge's response is derived from the digest it saw, so a test can
		// assert the judge ran LAST and on the panel outputs.
		last := lastUserContent(t, body)
		if strings.Contains(last, "answer-a") && strings.Contains(last, "answer-b") {
			return contentBody("JUDGED")
		}
		return contentBody("NO-DIGEST")
	}}
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": panel1, "b": panel2, "j": judge}}

	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyFusion,
		Panels: []contracts.Panel{
			{Label: "panel-1", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}},
			{Label: "panel-2", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1}},
		},
		Judge: &contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "j", Model: "m"}}, MaxRounds: 1},
	}
	d := newTestDispatcher(factory, credsFor("a", "b", "j"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	resp, err := d.Do(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := extractContent(resp.Wire.Body); got != "JUDGED" {
		t.Fatalf("final content = %q, want JUDGED (the judge's answer)", got)
	}
	if resp.Candidate.Provider != "j" {
		t.Fatalf("winner = %s, want the judge", resp.Candidate.Provider)
	}
	// The judge saw the anonymised digest and NOT the provider identity.
	if len(judge.reqs) != 1 {
		t.Fatalf("judge calls = %d, want 1", len(judge.reqs))
	}
	if !strings.Contains(judge.reqs[0], "panel-1") || !strings.Contains(judge.reqs[0], "panel-2") {
		t.Fatalf("judge request lacks anonymised labels: %s", judge.reqs[0])
	}
	if strings.Contains(judge.reqs[0], `"provider"`) || strings.Contains(judge.reqs[0], "cred-") {
		t.Fatalf("judge request leaked provenance: %s", judge.reqs[0])
	}
	// Both panels ran.
	if len(panel1.reqs) != 1 || len(panel2.reqs) != 1 {
		t.Fatalf("panel calls = %d / %d, want 1 each", len(panel1.reqs), len(panel2.reqs))
	}
}

// TestFusionPartialFailureStillJudges proves a failed panel is dropped and the
// judge runs on the survivors (ADR-0009 §3: partial success).
func TestFusionPartialFailureStillJudges(t *testing.T) {
	ok := &panelExecutor{family: "a", fn: func(string) string { return contentBody("ok-answer") }}
	// Provider "b" has NO executor entry, so its Build fails -> the panel fails.
	judge := &panelExecutor{family: "j", fn: func(body string) string {
		if strings.Contains(body, "ok-answer") {
			return contentBody("JUDGED")
		}
		return contentBody("MISS")
	}}
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": ok, "j": judge}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyFusion,
		Panels: []contracts.Panel{
			{Label: "panel-1", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}},
			{Label: "panel-2", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1}},
		},
		Judge: &contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "j", Model: "m"}}, MaxRounds: 1},
	}
	d := newTestDispatcher(factory, credsFor("a", "b", "j"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	resp, err := d.Do(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := extractContent(resp.Wire.Body); got != "JUDGED" {
		t.Fatalf("final content = %q, want JUDGED", got)
	}
}

// TestFusionAllFailedIsTypedError proves every panel failing yields the typed
// route.fusion_all_failed error.
func TestFusionAllFailedIsTypedError(t *testing.T) {
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyFusion,
		Panels: []contracts.Panel{
			{Label: "panel-1", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}},
			{Label: "panel-2", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1}},
		},
		Judge: &contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "j", Model: "m"}}, MaxRounds: 1},
	}
	d := newTestDispatcher(factory, credsFor("a", "b", "j"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), baseReq(), plan)
	de := asDomain(err)
	if de.Code != domain.CodeRouteFusionAllFailed {
		t.Fatalf("code = %q, want route.fusion_all_failed", de.Code)
	}
	if de.Params["panels"] != "2" {
		t.Fatalf("params = %+v", de.Params)
	}
}

// TestFusionFanoutCapRefused proves the Dispatcher's defensive cap.
func TestFusionFanoutCapRefused(t *testing.T) {
	panels := make([]contracts.Panel, maxFanout+1)
	for i := range panels {
		panels[i] = contracts.Panel{Label: "p", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}}
	}
	d := newTestDispatcher(&perProviderFactory{}, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), baseReq(), contracts.RoutePlan{Strategy: contracts.StrategyFusion, Panels: panels})
	if asDomain(err).Code != domain.CodeRouteFanoutExceeded {
		t.Fatalf("err = %v, want fanout_exceeded", err)
	}
}

// TestFusionNoJudgeReturnsFirstSuccessfulPanel proves the degenerate fallback
// (no judge route) returns a panel's response, and in streaming a one-chunk
// stream.
func TestFusionNoJudgeReturnsFirstSuccessfulPanel(t *testing.T) {
	panel := &panelExecutor{family: "a", fn: func(string) string { return contentBody("panel-answer") }}
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": panel}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyFusion,
		Panels: []contracts.Panel{
			{Label: "panel-1", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}},
		},
	}
	d := newTestDispatcher(factory, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	resp, err := d.Do(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := extractContent(resp.Wire.Body); got != "panel-answer" {
		t.Fatalf("content = %q", got)
	}

	stream, err := d.DoStream(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	ch, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if got := extractContent(ch.Data); got != "panel-answer" {
		t.Fatalf("stream content = %q", got)
	}
}

// TestFusionEmptyPanelsIsNoAttempts proves an empty panel set is a typed
// no-attempts error rather than a panic.
func TestFusionEmptyPanelsIsNoAttempts(t *testing.T) {
	d := newTestDispatcher(&perProviderFactory{}, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	// A plan with Panels nil does NOT dispatch to fusion; use a one-element
	// chain to reach the guard via a fusion marker. Instead call runFusion
	// directly through a Panels-bearing plan with a nil slice is not possible,
	// so drive runPanels via runFusion with a marker panel.
	plan := contracts.RoutePlan{Strategy: contracts.StrategyFusion, Panels: []contracts.Panel{}}
	if _, err := d.runFusion(context.Background(), baseReq(), plan, false); asDomain(err).Code != domain.CodeDispatchNoAttempts {
		t.Fatalf("err = %v, want no_attempts", err)
	}
}

// TestPipelineChainsAndReturnsLast proves the pipeline runs steps sequentially,
// feeding N's output to N+1, and only the LAST response reaches the caller.
func TestPipelineChainsAndReturnsLast(t *testing.T) {
	// Each step echoes its input's last user content, prefixed, so the chain is
	// observable end to end.
	step1 := &panelExecutor{family: "a", fn: func(body string) string {
		return contentBody("1(" + lastUserContent(t, body) + ")")
	}}
	step2 := &panelExecutor{family: "b", fn: func(body string) string {
		return contentBody("2(" + lastUserContent(t, body) + ")")
	}}
	step3 := &panelExecutor{family: "c", fn: func(body string) string {
		return contentBody("3(" + lastUserContent(t, body) + ")")
	}}
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": step1, "b": step2, "c": step3}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyPipeline,
		Chain: []contracts.RoutePlan{
			{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "c", Model: "m"}}, MaxRounds: 1},
		},
	}
	d := newTestDispatcher(factory, credsFor("a", "b", "c"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	resp, err := d.Do(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Only the LAST step's response is returned.
	if got := extractContent(resp.Wire.Body); got != "3(2(1(original)))" {
		t.Fatalf("final content = %q, want the chained last step", got)
	}
	if resp.Candidate.Provider != "c" {
		t.Fatalf("winner = %s, want the last step", resp.Candidate.Provider)
	}
	// Step 2 saw step 1's output, step 3 saw step 2's.
	if c := lastUserContent(t, step2.reqs[0]); !strings.Contains(c, "1(original)") {
		t.Fatalf("step2 input = %q, want step1 output", c)
	}
	if c := lastUserContent(t, step3.reqs[0]); !strings.Contains(c, "2(1(original))") {
		t.Fatalf("step3 input = %q, want step2 output", c)
	}
}

// TestPipelineOnlyLastStepStreams proves a streaming pipeline streams only the
// LAST step; the intermediate steps are non-streaming.
func TestPipelineOnlyLastStepStreams(t *testing.T) {
	// A step records whether it was called via DoStream; DoStream records too.
	streamAware := &streamAwareExecutor{family: "a"}
	streamB := &streamAwareExecutor{family: "b"}
	factory := &perProviderFactory2{execs: map[domain.ProviderID]*streamAwareExecutor{"a": streamAware, "b": streamB}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyPipeline,
		Chain: []contracts.RoutePlan{
			{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1},
		},
	}
	d := newTestDispatcher(factory2Adapter{factory}, credsFor("a", "b"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	stream, err := d.DoStream(context.Background(), baseReq(), plan)
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	// Drain.
	for {
		if _, rerr := stream.Recv(); rerr != nil {
			break
		}
	}
	if streamAware.streamCalls != 0 {
		t.Fatalf("intermediate step streamed (%d)", streamAware.streamCalls)
	}
	if streamB.streamCalls != 1 {
		t.Fatalf("last step stream calls = %d, want 1", streamB.streamCalls)
	}
}

// streamAwareExecutor counts Do and DoStream calls.
type streamAwareExecutor struct {
	family      domain.ProviderID
	doCalls     int
	streamCalls int
}

func (e *streamAwareExecutor) Family() domain.ProviderID { return e.family }
func (e *streamAwareExecutor) Do(_ context.Context, _ contracts.WireRequest, _ contracts.Credential) (contracts.WireResponse, error) {
	e.doCalls++
	return contracts.WireResponse{Status: 200, Body: []byte(contentBody("out-" + string(e.family)))}, nil
}
func (e *streamAwareExecutor) DoStream(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	e.streamCalls++
	resp, err := e.Do(ctx, req, cred)
	if err != nil {
		return nil, err
	}
	return &memStream{chunks: []contracts.Chunk{{Data: resp.Body}}}, nil
}
func (e *streamAwareExecutor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

// perProviderFactory2 adapts to ExecutorFactory for streamAwareExecutor.
type perProviderFactory2 struct {
	execs map[domain.ProviderID]*streamAwareExecutor
}

func (f *perProviderFactory2) Build(_ context.Context, c contracts.Candidate, _ contracts.Credential) (contracts.Executor, error) {
	if ex, ok := f.execs[c.Provider]; ok {
		return ex, nil
	}
	return nil, domain.New(domain.CodeProviderNotFound, domain.WithHTTPStatus(404))
}

// factory2Adapter widens *perProviderFactory2 to ExecutorFactory.
type factory2Adapter struct{ inner *perProviderFactory2 }

func (a factory2Adapter) Build(ctx context.Context, c contracts.Candidate, cred contracts.Credential) (contracts.Executor, error) {
	return a.inner.Build(ctx, c, cred)
}

// TestPipelineEmptyChainIsNoAttempts proves the empty-chain guard.
func TestPipelineEmptyChainIsNoAttempts(t *testing.T) {
	d := newTestDispatcher(&perProviderFactory{}, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	if _, err := d.runPipeline(context.Background(), baseReq(), contracts.RoutePlan{Strategy: contracts.StrategyPipeline}, false); asDomain(err).Code != domain.CodeDispatchNoAttempts {
		t.Fatalf("err = %v, want no_attempts", err)
	}
}

// TestPipelineStepFailureAborts proves a failing intermediate step aborts the
// chain (no later step runs, no client-visible intermediate).
func TestPipelineStepFailureAborts(t *testing.T) {
	step1 := &panelExecutor{family: "a", fn: func(string) string { return contentBody("x") }}
	// Provider "b" not registered -> step 2 Build fails.
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": step1}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyPipeline,
		Chain: []contracts.RoutePlan{
			{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1},
		},
	}
	d := newTestDispatcher(factory, credsFor("a", "b"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), baseReq(), plan)
	if err == nil {
		t.Fatal("pipeline succeeded with a failing step")
	}
}

// TestExtractContentBranches covers the content extractor's error/empty paths.
func TestExtractContentBranches(t *testing.T) {
	if got := extractContent([]byte("{bad")); got != "" {
		t.Fatalf("bad json = %q", got)
	}
	if got := extractContent([]byte(`{"choices":[]}`)); got != "" {
		t.Fatalf("no choices = %q", got)
	}
	if got := extractContent([]byte(`{"choices":[{"message":{"content":123}}]}`)); got != "" {
		t.Fatalf("non-string content = %q", got)
	}
	if got := extractContent([]byte(`{"choices":[{"message":{"content":"hi"}}]}`)); got != "hi" {
		t.Fatalf("content = %q", got)
	}
}

// TestChainRequestNonJSONLeavesBody proves a non-JSON base body is untouched.
func TestChainRequestNonJSONLeavesBody(t *testing.T) {
	base := contracts.WireRequest{Body: []byte("{bad")}
	got := chainRequest(base, []byte(contentBody("x")))
	if string(got.Body) != "{bad" {
		t.Fatalf("body = %s, want untouched", got.Body)
	}
	// A response with no content leaves the body unchanged too.
	got = chainRequest(baseReq(), []byte(`{"choices":[]}`))
	if string(got.Body) != string(baseReq().Body) {
		t.Fatalf("body = %s, want unchanged for empty content", got.Body)
	}
}

// TestJudgeRequestNonJSONLeavesBody proves the judge request guards a bad base.
func TestJudgeRequestNonJSONLeavesBody(t *testing.T) {
	got := judgeRequest(contracts.WireRequest{Body: []byte("{bad")}, nil)
	if string(got.Body) != "{bad" {
		t.Fatalf("body = %s, want untouched", got.Body)
	}
}

// TestPanelsDigestSkipsFailed proves a failed panel is omitted from the digest.
func TestPanelsDigestSkipsFailed(t *testing.T) {
	digest := panelsDigest([]panelResult{
		{panelOutput: panelOutput{label: "panel-1", content: "ok", ok: true}},
		{panelOutput: panelOutput{label: "panel-2", ok: false}},
	})
	if !strings.Contains(digest, "panel-1") || strings.Contains(digest, "panel-2") {
		t.Fatalf("digest = %q", digest)
	}
}

// TestSingleChunkStreamHeadersAndClose covers the fallback stream helpers.
func TestSingleChunkStreamHeadersAndClose(t *testing.T) {
	s := &singleChunkStream{body: []byte("x")}
	if s.Headers() == nil {
		t.Fatal("Headers nil")
	}
	if _, err := s.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if err := s.Close(); err != nil || !s.closed {
		t.Fatalf("Close = %v closed=%v", err, s.closed)
	}
}

// TestFanoutExceededShape covers the Dispatcher fanout error constructor.
func TestFanoutExceededShape(t *testing.T) {
	de := fanoutExceeded(9)
	if de.Code != domain.CodeRouteFanoutExceeded || de.Params["max"] != "8" {
		t.Fatalf("err = %+v", de)
	}
}

// TestFirstSuccessfulPanelUnreachable proves the total fallback returns a zero
// outcome rather than panicking when called with no successes.
func TestFirstSuccessfulPanelUnreachable(t *testing.T) {
	if got := firstSuccessfulPanel(nil, false); got == nil {
		t.Fatal("firstSuccessfulPanel returned nil")
	}
}

// TestFusionJudgeErrorPropagates proves a judge failure surfaces from fusion.
func TestFusionJudgeErrorPropagates(t *testing.T) {
	panel := &panelExecutor{family: "a", fn: func(string) string { return contentBody("x") }}
	// The judge provider is unregistered, so building its executor fails and the
	// judge attempt is exhausted.
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"a": panel}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyFusion,
		Panels: []contracts.Panel{
			{Label: "panel-1", Plan: contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1}},
		},
		Judge: &contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "ghost", Model: "m"}}, MaxRounds: 1},
	}
	d := newTestDispatcher(factory, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	if _, err := d.Do(context.Background(), baseReq(), plan); err == nil {
		t.Fatal("fusion succeeded despite a failing judge")
	}
}

// TestJudgeAndChainMarshalSeam exercises the best-effort marshal-failure guards:
// with a failing marshal, both request builders leave the body untouched rather
// than dropping the request. Each of the three judgeRequest marshal calls and
// the three chainRequest calls is failed in turn.
func TestJudgeAndChainMarshalSeam(t *testing.T) {
	orig := jsonMarshal
	defer func() { jsonMarshal = orig }()
	panels := []panelResult{{panelOutput: panelOutput{label: "panel-1", content: "c", ok: true}}}

	failNth := func(n int) {
		seen := 0
		jsonMarshal = func(v any) ([]byte, error) {
			seen++
			if seen == n {
				return nil, &marshalError{}
			}
			return json.Marshal(v)
		}
	}
	for n := 1; n <= 3; n++ {
		failNth(n) // fresh counter for judgeRequest
		if got := judgeRequest(baseReq(), panels); string(got.Body) != string(baseReq().Body) {
			t.Fatalf("judgeRequest marshal call %d: body changed on failure", n)
		}
		failNth(n) // fresh counter for chainRequest
		if got := chainRequest(baseReq(), []byte(contentBody("step-out"))); string(got.Body) != string(baseReq().Body) {
			t.Fatalf("chainRequest marshal call %d: body changed on failure", n)
		}
	}
}

// marshalError is the injected marshal failure.
type marshalError struct{}

func (*marshalError) Error() string { return "marshal boom" }

// TestPipelineEmptyStepSkipped proves a pipeline whose only step is empty
// surfaces the linear loop's no-attempts error.
func TestPipelineEmptyStepSkipped(t *testing.T) {
	// An empty step plan still executes through the linear loop, which returns
	// no_attempts; the pipeline surfaces it.
	d := newTestDispatcher(&perProviderFactory{}, credsFor("a"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	plan := contracts.RoutePlan{Strategy: contracts.StrategyPipeline, Chain: []contracts.RoutePlan{{}}}
	if _, err := d.Do(context.Background(), baseReq(), plan); err == nil {
		t.Fatal("pipeline with an empty step succeeded")
	}
}

// TestFirstSuccessfulPanelSkipsFailed covers the failed-panel skip.
func TestFirstSuccessfulPanelSkipsFailed(t *testing.T) {
	got := firstSuccessfulPanel([]panelResult{
		{panelOutput: panelOutput{label: "panel-1", ok: false}},
		{panelOutput: panelOutput{label: "panel-2", ok: true}, candidate: contracts.Candidate{Provider: "a"}, body: []byte("x")},
	}, false)
	if got.candidate.Provider != "a" {
		t.Fatalf("firstSuccessfulPanel = %+v, want the second (ok) panel", got)
	}
}

// TestSingleChunkStreamRecvThenEOF covers the second Recv returning io.EOF.
func TestSingleChunkStreamRecvThenEOF(t *testing.T) {
	s := &singleChunkStream{body: []byte("x")}
	if _, err := s.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want io.EOF", err)
	}
}

// TestPipelineIntermediateStepFailure proves a failing intermediate step aborts
// before the last step runs.
func TestPipelineIntermediateStepFailure(t *testing.T) {
	step3 := &panelExecutor{family: "c", fn: func(string) string { return contentBody("never") }}
	// Provider "b" (the middle step) is unregistered, so step 2 fails.
	factory := &perProviderFactory{execs: map[domain.ProviderID]*panelExecutor{"c": step3}}
	plan := contracts.RoutePlan{
		Strategy: contracts.StrategyPipeline,
		Chain: []contracts.RoutePlan{
			{Attempts: []contracts.Candidate{{Provider: "a", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "b", Model: "m"}}, MaxRounds: 1},
			{Attempts: []contracts.Candidate{{Provider: "c", Model: "m"}}, MaxRounds: 1},
		},
	}
	d := newTestDispatcher(factory, credsFor("a", "b", "c"), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	if _, err := d.Do(context.Background(), baseReq(), plan); err == nil {
		t.Fatal("pipeline succeeded with a failing intermediate step")
	}
	if len(step3.reqs) != 0 {
		t.Fatal("the last step ran after an intermediate failure")
	}
}

// keep http import used by the response status constant.
var _ = http.StatusOK
