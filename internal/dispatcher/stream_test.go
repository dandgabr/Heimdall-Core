package dispatcher

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestDoStreamWinsFirstCandidate proves the stream is returned from the first
// candidate and that the winner is fixed (committed).
func TestDoStreamWinsFirstCandidate(t *testing.T) {
	ms := &memStream{chunks: []contracts.Chunk{{Data: []byte(`{"choices":[]}`)}}}
	ex := &fakeExecutor{family: "p1", streams: []streamResult{{stream: ms}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	stream, err := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	ws, ok := stream.(*wrappingStream)
	if !ok || ws.inner != ms {
		t.Fatalf("stream = %T, want a wrappingStream over the winner", stream)
	}
	if ex.stCalls != 1 {
		t.Fatalf("stream calls = %d, want 1", ex.stCalls)
	}
}

// TestDoStreamPreCommitFailover proves a pre-commit stream error fails over.
func TestDoStreamPreCommitFailover(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", streams: []streamResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}}}
	ms2 := &memStream{chunks: []contracts.Chunk{{Data: []byte("data")}}}
	ex2 := &fakeExecutor{family: "p2", streams: []streamResult{{stream: ms2}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	stream, err := d.DoStream(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	ws, ok := stream.(*wrappingStream)
	if !ok || ws.inner != ms2 {
		t.Fatalf("stream did not fail over: %T", stream)
	}
}

// TestDoStreamClientErrorTerminal proves a pre-commit client error returns
// immediately.
func TestDoStreamClientErrorTerminal(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", streams: []streamResult{{err: domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(400), domain.WithScope(domain.ScopeRequest))}}}
	ex2 := &fakeExecutor{family: "p2", streams: []streamResult{{stream: &memStream{}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	if _, err := d.DoStream(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2"))); err == nil {
		t.Fatal("client error did not propagate from DoStream")
	}
	if ex2.stCalls != 0 {
		t.Fatal("client error failed over on the stream path")
	}
}

// TestDoStreamAccountsOnCleanEOF proves a clean stream accounts a success usage.
func TestDoStreamAccountsOnCleanEOF(t *testing.T) {
	ms := &memStream{chunks: []contracts.Chunk{{Data: []byte(`{"usage":{"total_tokens":12}}`)}}}
	ex := &fakeExecutor{family: "p1", streams: []streamResult{{stream: ms}}}
	rec := newFakeRecorder()
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, rec, &fakeWaiter{})

	stream, err := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	// Drain to EOF.
	for {
		if _, rerr := stream.Recv(); rerr != nil {
			break
		}
	}
	u, ok := rec.usage("req-1:p1/m:c1:1")
	if !ok || u.Tokens != 12 || u.Aborted {
		t.Fatalf("stream usage = %+v, want 12 tokens clean", u)
	}
}

// TestDoStreamAccountsAborted proves a mid-stream error accounts an aborted use
// (the tokens observed before the abort), never zero.
func TestDoStreamAccountsAborted(t *testing.T) {
	midErr := domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(502), domain.WithScope(domain.ScopeProvider))
	ms := &memStream{
		chunks: []contracts.Chunk{{Data: []byte(`{"usage":{"total_tokens":5}}`)}},
		err:    midErr,
	}
	ex := &fakeExecutor{family: "p1", streams: []streamResult{{stream: ms}}}
	rec := newFakeRecorder()
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, rec, &fakeWaiter{})

	stream, err := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	for {
		if _, rerr := stream.Recv(); rerr != nil {
			if !errors.Is(rerr, midErr) {
				t.Fatalf("Recv error = %v, want the mid-stream error", rerr)
			}
			break
		}
	}
	u, ok := rec.usage("req-1:p1/m:c1:1")
	if !ok || u.Tokens != 5 || !u.Aborted {
		t.Fatalf("aborted usage = %+v, want 5 tokens aborted", u)
	}
}

// TestDoStreamCloseWithoutEOFAccountsAbort proves Close without EOF is an abort.
func TestDoStreamCloseWithoutEOFAccountsAbort(t *testing.T) {
	ms := &memStream{chunks: []contracts.Chunk{{Data: []byte(`{"usage":{"total_tokens":3}}`)}}}
	ex := &fakeExecutor{family: "p1", streams: []streamResult{{stream: ms}}}
	rec := newFakeRecorder()
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, rec, &fakeWaiter{})

	stream, err := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	// Read one chunk then close before EOF (a client disconnect).
	if _, rerr := stream.Recv(); rerr != nil {
		t.Fatalf("first Recv: %v", rerr)
	}
	if cerr := stream.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	if !ms.closed {
		t.Fatal("Close did not close the inner stream")
	}
	u, ok := rec.usage("req-1:p1/m:c1:1")
	if !ok || !u.Aborted {
		t.Fatalf("usage after close = %+v, want aborted", u)
	}
	// Accounting is once: a second Close does not add a usage.
	_ = stream.Close()
	if rec.count() != 1 {
		t.Fatalf("recorded attempts = %d, want 1 (accounted once)", rec.count())
	}
}

// TestWrappingStreamHeadersForwards proves Headers is delegated.
func TestWrappingStreamHeadersForwards(t *testing.T) {
	ms := &memStream{}
	rec := newFakeRecorder()
	d := &Dispatcher{recorder: rec}
	wrapped := d.wrapStream(ms, cand("p", "m", "c"), "k")
	if wrapped.Headers() == nil {
		t.Fatal("Headers returned nil")
	}
}

// TestWrapStreamNilRecorderPassthrough proves a nil recorder returns the raw
// stream (no accounting wrapper).
func TestWrapStreamNilRecorderPassthrough(t *testing.T) {
	ms := &memStream{}
	d := &Dispatcher{}
	if got := d.wrapStream(ms, cand("p", "m", "c"), "k"); got != ms {
		t.Fatal("nil recorder still wrapped the stream")
	}
}

// TestWrappingStreamAbsorbIgnoresNonUsage covers absorb's early returns.
func TestWrappingStreamAbsorbIgnoresNonUsage(t *testing.T) {
	ws := &wrappingStream{}
	ws.absorb(nil)
	ws.absorb([]byte("no usage here"))
	ws.absorb([]byte(`{"usage":` + "bad"))
	if ws.tokens != 0 {
		t.Fatalf("absorb accumulated tokens from a bad chunk: %d", ws.tokens)
	}
	// Anthropic-shaped chunk.
	ws.absorb([]byte(`{"usage":{"input_tokens":2,"output_tokens":3}}`))
	if ws.tokens != 5 {
		t.Fatalf("absorb anthropic = %d, want 5", ws.tokens)
	}
}

// TestDoStreamExhausted proves a streamed plan with all-failed candidates
// returns the aggregate.
func TestDoStreamExhausted(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", streams: []streamResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}}}
	ex2 := &fakeExecutor{family: "p2", streams: []streamResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	_, err := d.DoStream(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if asDomain(err).Code != domain.CodeDispatchExhausted {
		t.Fatalf("err = %v, want dispatch.exhausted", err)
	}
}

// TestDoStreamContextCancelled proves a cancelled ctx during a streamed cooldown
// returns the ctx error.
func TestDoStreamContextCancelled(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", streams: []streamResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(429), domain.Retry(), domain.WithScope(domain.ScopeCredential),
		domain.WithRetryAfter(time.Second))}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1}}
	waiter := &fakeWaiter{err: context.Canceled}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), waiter)

	_, err := d.DoStream(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if asDomain(err).Code != domain.CodeUpstreamTimeout {
		t.Fatalf("err = %v, want upstream_timeout", err)
	}
}

// TestDoStreamNoAttempts proves a fully-filtered streamed plan yields the
// no-attempts aggregate.
func TestDoStreamNoAttempts(t *testing.T) {
	br := newFakeBreaker()
	br.allow[keyOf(cand("p1", "m", "c1"))] = false
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), br, nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if asDomain(err).Code != domain.CodeDispatchNoAttempts {
		t.Fatalf("err = %v, want dispatch.no_attempts", err)
	}
}

// TestDoStreamEOFIsNotAnError covers the io.EOF path being treated as a clean
// end when the wrapping stream is drained.
func TestDoStreamEOFIsNotAnError(t *testing.T) {
	ms := &memStream{} // immediately EOF
	ex := &fakeExecutor{family: "p1", streams: []streamResult{{stream: ms}}}
	rec := newFakeRecorder()
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, rec, &fakeWaiter{})
	stream, _ := d.DoStream(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("Recv on empty stream = %v, want io.EOF", err)
	}
}
