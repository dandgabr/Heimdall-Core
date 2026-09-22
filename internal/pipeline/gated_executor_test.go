package pipeline

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// --- fakes ---

// fakeExecutor is a contracts.Executor that records whether it was called and
// returns canned results. It is the inner executor the gated decorator wraps.
type fakeExecutor struct {
	family         domain.ProviderID
	doCalled       bool
	doStreamCalled bool
	countCalled    bool
	doReq          contracts.WireRequest
	doCred         contracts.Credential
	doResp         contracts.WireResponse
	doErr          error
	stream         contracts.Stream
	streamErr      error
	count          int
	countErr       error
}

func (f *fakeExecutor) Family() domain.ProviderID { return f.family }

func (f *fakeExecutor) Do(_ context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.WireResponse, error) {
	f.doCalled = true
	f.doReq = req
	f.doCred = cred
	return f.doResp, f.doErr
}

func (f *fakeExecutor) DoStream(_ context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	f.doStreamCalled = true
	f.doReq = req
	f.doCred = cred
	return f.stream, f.streamErr
}

func (f *fakeExecutor) CountTokens(_ context.Context, _ contracts.WireRequest, _ domain.ModelID) (int, error) {
	f.countCalled = true
	return f.count, f.countErr
}

// fakeStream is a contracts.Stream that yields canned chunks and counts Close.
type fakeStream struct {
	headers  http.Header
	chunks   []contracts.Chunk
	idx      int
	err      error
	closes   int
	closeErr error
}

func (s *fakeStream) Headers() http.Header { return s.headers }

func (s *fakeStream) Recv() (contracts.Chunk, error) {
	if s.idx < len(s.chunks) {
		ch := s.chunks[s.idx]
		s.idx++
		return ch, nil
	}
	if s.err != nil {
		return contracts.Chunk{}, s.err
	}
	return contracts.Chunk{}, io.EOF
}

func (s *fakeStream) Close() error {
	s.closes++
	return s.closeErr
}

// orderGate is a gate that appends its stage name to a shared trace.
func orderGate(id string, trace *[]string) *recordingGate {
	return &recordingGate{
		id:     id,
		stages: contracts.StageSet(contracts.StagePreRequest, contracts.StagePostResponse),
		policy: contracts.FailOpen,
		pre: func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			*trace = append(*trace, "pre")
			return contracts.Decision{Kind: contracts.DecisionContinue}, nil
		},
		post: func(context.Context, contracts.GateInput) error {
			*trace = append(*trace, "post")
			return nil
		},
	}
}

func cred() contracts.Credential {
	return contracts.Credential{ID: "cred-1", Provider: "z.ai"}
}

// --- NewGatedExecutor ---

// TestNewGatedExecutorRejectsNil covers both nil-argument branches.
func TestNewGatedExecutorRejectsNil(t *testing.T) {
	chain, _ := New(nil)

	_, err := NewGatedExecutor(nil, chain)
	if !hasCode(err, domain.CodeInternal) {
		t.Fatalf("nil inner err = %v, want %s", err, domain.CodeInternal)
	}

	_, err = NewGatedExecutor(&fakeExecutor{}, nil)
	if !hasCode(err, domain.CodeInternal) {
		t.Fatalf("nil chain err = %v, want %s", err, domain.CodeInternal)
	}

	g, err := NewGatedExecutor(&fakeExecutor{}, chain)
	if err != nil || g == nil {
		t.Fatalf("valid build: %v", err)
	}
}

// TestGatedExecutorFamilyDelegates covers Family's delegation.
func TestGatedExecutorFamilyDelegates(t *testing.T) {
	g, _ := NewGatedExecutor(&fakeExecutor{family: "z.ai"}, mustChain(t))
	if g.Family() != "z.ai" {
		t.Fatalf("Family = %q", g.Family())
	}
}

// TestGatedExecutorCountTokensDelegates covers CountTokens' delegation.
func TestGatedExecutorCountTokensDelegates(t *testing.T) {
	inner := &fakeExecutor{family: "z", count: 7}
	g, _ := NewGatedExecutor(inner, mustChain(t))
	n, err := g.CountTokens(context.Background(), contracts.WireRequest{}, "m")
	if err != nil || n != 7 {
		t.Fatalf("CountTokens = %d, %v", n, err)
	}
	if !inner.countCalled {
		t.Fatal("inner CountTokens not called")
	}
}

func mustChain(t *testing.T) *Chain {
	t.Helper()
	c, err := New(nil)
	if err != nil {
		t.Fatalf("New chain: %v", err)
	}
	return c
}

// --- gateInput (metadata-only) ---

// TestGatedExecutorInputIsMetadataOnly pins SEC-13 at the executor boundary: the
// gate sees header NAMES with empty values, never the body, and the family in
// Meta.
func TestGatedExecutorInputIsMetadataOnly(t *testing.T) {
	var captured contracts.GateInput
	gate := &recordingGate{
		id: "capture", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen,
		pre: func(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
			captured = in
			return contracts.Decision{Kind: contracts.DecisionContinue}, nil
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	g, _ := NewGatedExecutor(&fakeExecutor{family: "z.ai", doResp: contracts.WireResponse{Status: 200}}, chain)

	req := contracts.WireRequest{
		Body:    []byte(`{"secret":"payload"}`),
		Model:   "m1",
		Headers: http.Header{"Authorization": {"Bearer SUPER-SECRET"}, "X-Trace": {"abc"}},
	}
	if _, err := g.Do(context.Background(), req, cred()); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if captured.Body != nil {
		t.Errorf("gate saw the body: %q", captured.Body)
	}
	for name, vals := range captured.Headers {
		for _, v := range vals {
			if v != "" {
				t.Errorf("header %s carried a value %q", name, v)
			}
		}
	}
	if _, ok := captured.Headers["Authorization"]; !ok {
		t.Error("Authorization name missing from the gate view")
	}
	if captured.Meta["executor.family"] != "z.ai" {
		t.Errorf("Meta family = %q", captured.Meta["executor.family"])
	}
	if captured.Provider != "z.ai" || captured.Credential != "cred-1" || captured.Model != "m1" {
		t.Errorf("metadata = %+v", captured)
	}
}

// --- Do ---

// TestGatedExecutorDoRunsPreThenInnerThenPost covers the success path ordering.
func TestGatedExecutorDoRunsPreThenInnerThenPost(t *testing.T) {
	var trace []string
	gate := orderGate("g", &trace)
	chain, _ := New([]contracts.Gate{gate})

	inner := &fakeExecutor{family: "z", doResp: contracts.WireResponse{Status: 200, Body: []byte("ok")}}
	g, _ := NewGatedExecutor(inner, chain)

	resp, err := g.Do(context.Background(), contracts.WireRequest{Model: "m"}, cred())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !inner.doCalled {
		t.Fatal("inner Do not called")
	}
	if string(resp.Body) != "ok" || resp.Status != 200 {
		t.Fatalf("resp = %+v", resp)
	}
	if len(trace) != 2 || trace[0] != "pre" || trace[1] != "post" {
		t.Fatalf("trace = %v, want [pre post]", trace)
	}
}

// TestGatedExecutorDoBlockReturnsSyntheticSuccess covers gateInput -> chain Block
// -> syntheticFromDecision: the inner is NOT called and the Synthetic is a
// successful response, not an error.
func TestGatedExecutorDoBlockReturnsSyntheticSuccess(t *testing.T) {
	gate := preOnly("cache", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{
			Kind: contracts.DecisionBlock,
			Synthetic: &contracts.SyntheticResponse{
				Status: http.StatusOK, Body: []byte("cached"), CacheHit: true,
			},
		}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z"}
	g, _ := NewGatedExecutor(inner, chain)

	resp, err := g.Do(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("Block returned an error: %v", err)
	}
	if inner.doCalled {
		t.Error("inner was called despite a Block")
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "cached" {
		t.Fatalf("resp = %+v", resp)
	}
}

// TestSyntheticFromDecisionDefaultsStatus covers the status==0 -> 200 branch.
func TestSyntheticFromDecisionDefaultsStatus(t *testing.T) {
	got, blocked := syntheticFromDecision(contracts.Decision{
		Kind:      contracts.DecisionBlock,
		Synthetic: &contracts.SyntheticResponse{Body: []byte("x")},
	})
	if !blocked || got.Status != http.StatusOK {
		t.Fatalf("got = %+v, blocked = %v, want status 200", got, blocked)
	}

	if _, blocked := syntheticFromDecision(contracts.Decision{Kind: contracts.DecisionContinue}); blocked {
		t.Fatal("a Continue decision was treated as a block")
	}
}

// TestGatedExecutorDoFailClosed covers a FailClosed gate error: Do returns it and
// the inner never runs.
func TestGatedExecutorDoFailClosed(t *testing.T) {
	boom := errors.New("gate denied")
	gate := preOnly("closed", contracts.FailClosed, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, boom
	})
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z"}
	g, _ := NewGatedExecutor(inner, chain)

	_, err := g.Do(context.Background(), contracts.WireRequest{}, cred())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the gate error", err)
	}
	if inner.doCalled {
		t.Error("inner ran despite a FailClosed error")
	}
}

// TestGatedExecutorDoFailOpenContinues covers a FailOpen gate error: the pipeline
// continues to the inner.
func TestGatedExecutorDoFailOpenContinues(t *testing.T) {
	gate := preOnly("open", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, errors.New("gate flaked")
	})
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", doResp: contracts.WireResponse{Status: 200}}
	g, _ := NewGatedExecutor(inner, chain)

	if _, err := g.Do(context.Background(), contracts.WireRequest{}, cred()); err != nil {
		t.Fatalf("FailOpen aborted: %v", err)
	}
	if !inner.doCalled {
		t.Error("inner did not run after a FailOpen error")
	}
}

// TestGatedExecutorDoInnerErrorStillRunsPost covers the best-effort PostResponse
// on the inner error path: the original error is preserved.
func TestGatedExecutorDoInnerErrorStillRunsPost(t *testing.T) {
	var trace []string
	gate := orderGate("g", &trace)
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", doErr: errors.New("upstream down")}
	g, _ := NewGatedExecutor(inner, chain)

	_, err := g.Do(context.Background(), contracts.WireRequest{}, cred())
	if err == nil {
		t.Fatal("expected the inner error")
	}
	if len(trace) != 2 || trace[1] != "post" {
		t.Fatalf("trace = %v, want PostResponse after the error", trace)
	}
}

// --- DoStream ---

// TestGatedExecutorDoStreamDelegatesAndRunsPostOnClose covers the success path:
// the returned stream delegates Recv/Headers to the inner, and Close closes the
// inner once and runs PostResponse once.
func TestGatedExecutorDoStreamDelegatesAndRunsPostOnClose(t *testing.T) {
	var trace []string
	gate := orderGate("g", &trace)
	chain, _ := New([]contracts.Gate{gate})

	innerStream := &fakeStream{
		headers: http.Header{"Content-Type": {"text/event-stream"}},
		chunks:  []contracts.Chunk{{Data: []byte("a")}, {Data: []byte("b")}},
	}
	inner := &fakeExecutor{family: "z", stream: innerStream}
	g, _ := NewGatedExecutor(inner, chain)

	stream, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	if !inner.doStreamCalled {
		t.Fatal("inner DoStream not called")
	}
	if stream.Headers().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("headers not delegated: %v", stream.Headers())
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("third Recv = %v, want EOF", err)
	}
	// PostResponse must not have run before Close.
	if len(trace) != 1 {
		t.Fatalf("trace before Close = %v, want [pre]", trace)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent: inner closed once, hook once.
	_ = stream.Close()
	if innerStream.closes != 1 {
		t.Errorf("inner Close called %d times, want 1", innerStream.closes)
	}
	if len(trace) != 2 || trace[1] != "post" {
		t.Fatalf("trace = %v, want PostResponse once on Close", trace)
	}
}

// TestGatedExecutorDoStreamBlockReturnsSyntheticStream covers the pre-commit
// Block on the streaming path: a single-chunk synthetic stream, and PostResponse
// on Close.
func TestGatedExecutorDoStreamBlockReturnsSyntheticStream(t *testing.T) {
	trace := []string{}
	gate := &recordingGate{
		id: "cache", stages: contracts.StageSet(contracts.StagePreRequest, contracts.StagePostResponse), policy: contracts.FailOpen,
		pre: func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			trace = append(trace, "pre")
			return contracts.Decision{
				Kind:      contracts.DecisionBlock,
				Synthetic: &contracts.SyntheticResponse{Status: 200, Body: []byte("hit")},
			}, nil
		},
		post: func(context.Context, contracts.GateInput) error {
			trace = append(trace, "post")
			return nil
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z"}
	g, _ := NewGatedExecutor(inner, chain)

	stream, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	if inner.doStreamCalled {
		t.Error("inner was called despite a Block")
	}
	ch, err := stream.Recv()
	if err != nil {
		t.Fatalf("synthetic Recv: %v", err)
	}
	if string(ch.Data) != "hit" || ch.Event != "message" {
		t.Fatalf("synthetic chunk = %+v", ch)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
	if len(trace) != 1 {
		t.Fatalf("trace before Close = %v, want [pre]", trace)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = stream.Close()
	if len(trace) != 2 {
		t.Fatalf("trace = %v, want PostResponse exactly once", trace)
	}
}

// TestGatedExecutorDoStreamInnerErrorRunsPost covers the inner DoStream error:
// PostResponse runs and the error is preserved.
func TestGatedExecutorDoStreamInnerErrorRunsPost(t *testing.T) {
	var trace []string
	gate := orderGate("g", &trace)
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", streamErr: errors.New("dial failed")}
	g, _ := NewGatedExecutor(inner, chain)

	if _, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred()); err == nil {
		t.Fatal("expected the inner error")
	}
	if len(trace) != 2 || trace[1] != "post" {
		t.Fatalf("trace = %v, want PostResponse after the error", trace)
	}
}

// TestGatedExecutorDoStreamFailPolicies covers FailClosed and FailOpen on the
// streaming path.
func TestGatedExecutorDoStreamFailPolicies(t *testing.T) {
	boom := errors.New("stream gate boom")

	t.Run("fail closed", func(t *testing.T) {
		gate := preOnly("closed", contracts.FailClosed, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{}, boom
		})
		chain, _ := New([]contracts.Gate{gate})
		inner := &fakeExecutor{family: "z"}
		g, _ := NewGatedExecutor(inner, chain)
		if _, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred()); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the gate error", err)
		}
		if inner.doStreamCalled {
			t.Error("inner ran despite a FailClosed error")
		}
	})

	t.Run("fail open", func(t *testing.T) {
		gate := preOnly("open", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{}, boom
		})
		chain, _ := New([]contracts.Gate{gate})
		inner := &fakeExecutor{family: "z", stream: &fakeStream{}}
		g, _ := NewGatedExecutor(inner, chain)
		if _, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred()); err != nil {
			t.Fatalf("FailOpen aborted: %v", err)
		}
		if !inner.doStreamCalled {
			t.Error("inner did not run after a FailOpen error")
		}
	})
}

// TestGatedExecutorDoRerouteIsExplicit is the P2 regression: a DecisionReroute
// must never be silently ignored. The inner is NOT called and a typed error is
// returned, since the F3 Dispatcher (allowlist validation) does not exist yet.
func TestGatedExecutorDoRerouteIsExplicit(t *testing.T) {
	gate := preOnly("rerouter", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{
			Kind:    contracts.DecisionReroute,
			Reroute: &contracts.RerouteTarget{Provider: "other", Model: "m"},
		}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", doResp: contracts.WireResponse{Status: 200}}
	g, _ := NewGatedExecutor(inner, chain)

	resp, err := g.Do(context.Background(), contracts.WireRequest{}, cred())
	if err == nil {
		t.Fatal("reroute was silently ignored (no error)")
	}
	if !hasCode(err, domain.CodeProviderRerouteUnsupported) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderRerouteUnsupported)
	}
	if inner.doCalled {
		t.Error("inner ran with the original request despite a reroute")
	}
	if resp.Status != 0 || resp.Body != nil {
		t.Errorf("resp = %+v, want the zero response", resp)
	}
}

// TestGatedExecutorDoStreamRerouteIsExplicit covers the streaming path: a
// reroute returns the typed error and never opens the inner stream.
func TestGatedExecutorDoStreamRerouteIsExplicit(t *testing.T) {
	gate := preOnly("rerouter", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{
			Kind:    contracts.DecisionReroute,
			Reroute: &contracts.RerouteTarget{Provider: "other", Model: "m"},
		}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", stream: &fakeStream{}}
	g, _ := NewGatedExecutor(inner, chain)

	if _, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred()); !hasCode(err, domain.CodeProviderRerouteUnsupported) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderRerouteUnsupported)
	}
	if inner.doStreamCalled {
		t.Error("inner stream opened despite a reroute")
	}
}

// TestGatedExecutorDoStreamAppliesChunkGates is the P1 regression: the stream
// wrapper must run OnResponseChunk per chunk. A Drop gate discards a chunk and a
// Replace gate swaps its Data, both visible to the consumer.
func TestGatedExecutorDoStreamAppliesChunkGates(t *testing.T) {
	// Drop every chunk whose data is "drop"; replace "old" with "new".
	gate := &recordingGate{
		id:     "chunk",
		stages: contracts.StageSet(contracts.StageOnResponseChunk),
		policy: contracts.FailOpen,
		chunk: func(_ context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
			switch string(in.Body) {
			case "drop":
				return contracts.ChunkDecision{Kind: contracts.ChunkDrop}, nil
			case "old":
				return contracts.ChunkDecision{Kind: contracts.ChunkReplace, Body: []byte("new")}, nil
			default:
				return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
			}
		},
	}
	chain, _ := New([]contracts.Gate{gate})

	inner := &fakeExecutor{family: "z", stream: &fakeStream{
		chunks: []contracts.Chunk{
			{Data: []byte("drop")},
			{Data: []byte("keep")},
			{Data: []byte("old")},
		},
	}}
	g, _ := NewGatedExecutor(inner, chain)
	stream, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	var got []string
	for {
		ch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		got = append(got, string(ch.Data))
	}
	if len(got) != 2 || got[0] != "keep" || got[1] != "new" {
		t.Fatalf("chunks = %v, want [keep new] (drop discarded, replace applied)", got)
	}
}

// TestGatedExecutorChunkGateFailClosed covers a FailClosed chunk gate: the error
// surfaces to the consumer.
func TestGatedExecutorChunkGateFailClosed(t *testing.T) {
	boom := errors.New("chunk denied")
	gate := &recordingGate{
		id:     "chunk",
		stages: contracts.StageSet(contracts.StageOnResponseChunk),
		policy: contracts.FailClosed,
		chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
			return contracts.ChunkDecision{}, boom
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", stream: &fakeStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}
	g, _ := NewGatedExecutor(inner, chain)
	stream, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Recv(); !errors.Is(err, boom) {
		t.Fatalf("Recv = %v, want the FailClosed gate error", err)
	}
}

// TestGatedExecutorChunkGateFailOpenContinues covers a FailOpen chunk gate: the
// error is swallowed and the chunk passes through.
func TestGatedExecutorChunkGateFailOpenContinues(t *testing.T) {
	gate := &recordingGate{
		id:     "chunk",
		stages: contracts.StageSet(contracts.StageOnResponseChunk),
		policy: contracts.FailOpen,
		chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
			return contracts.ChunkDecision{}, errors.New("flaked")
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	inner := &fakeExecutor{family: "z", stream: &fakeStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}
	g, _ := NewGatedExecutor(inner, chain)
	stream, err := g.DoStream(context.Background(), contracts.WireRequest{}, cred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	ch, err := stream.Recv()
	if err != nil || string(ch.Data) != "x" {
		t.Fatalf("FailOpen chunk = %+v, %v", ch, err)
	}
}

// hasCode mirrors the helper used across the suite.
func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}
