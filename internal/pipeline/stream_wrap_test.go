package pipeline

import (
	"io"
	"net/http"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// TestSyntheticStreamHeadersDelegates covers Headers on the synthetic stream.
func TestSyntheticStreamHeadersDelegates(t *testing.T) {
	h := http.Header{"X-Synthetic": {"1"}}
	s := &syntheticStream{headers: h}
	if s.Headers().Get("X-Synthetic") != "1" {
		t.Fatalf("Headers = %v", s.Headers())
	}
}

// TestSyntheticStreamRecvOneChunkThenEOF covers Recv on the synthetic stream:
// one chunk carrying the body, then io.EOF forever.
func TestSyntheticStreamRecvOneChunkThenEOF(t *testing.T) {
	s := &syntheticStream{body: []byte("cached")}
	ch, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(ch.Data) != "cached" || ch.Event != "message" {
		t.Fatalf("chunk = %+v", ch)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("third Recv = %v, want EOF (terminal)", err)
	}
}

// TestSyntheticStreamCloseRunsHookOnce covers Close: idempotent, hook once, and
// a nil hook is safe.
func TestSyntheticStreamCloseRunsHookOnce(t *testing.T) {
	calls := 0
	s := &syntheticStream{onClose: func() { calls++ }}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = s.Close()
	_ = s.Close()
	if calls != 1 {
		t.Fatalf("onClose called %d times, want 1", calls)
	}

	nilHook := &syntheticStream{}
	if err := nilHook.Close(); err != nil {
		t.Fatalf("nil-hook Close: %v", err)
	}
}

// TestClosingStreamDelegates covers the embedded Stream delegation on
// closingStream: Headers and Recv pass straight through to the inner.
func TestClosingStreamDelegates(t *testing.T) {
	inner := &fakeStream{
		headers: http.Header{"X-Inner": {"v"}},
		chunks:  []contracts.Chunk{{Data: []byte("one")}},
	}
	s := &closingStream{Stream: inner}

	if s.Headers().Get("X-Inner") != "v" {
		t.Fatalf("Headers = %v", s.Headers())
	}
	ch, err := s.Recv()
	if err != nil || string(ch.Data) != "one" {
		t.Fatalf("Recv = %+v, %v", ch, err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
}

// TestClosingStreamCloseOnceAndHook covers Close: the inner is closed once, the
// hook runs once, and the inner's error is propagated.
func TestClosingStreamCloseOnceAndHook(t *testing.T) {
	inner := &fakeStream{closeErr: io.ErrClosedPipe}
	calls := 0
	s := &closingStream{Stream: inner, onClose: func() { calls++ }}

	if err := s.Close(); err != io.ErrClosedPipe {
		t.Fatalf("Close = %v, want the inner error", err)
	}
	// Idempotent: the second call must not re-close nor re-run the hook.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil (already closed)", err)
	}
	if inner.closes != 1 {
		t.Errorf("inner Close called %d times, want 1", inner.closes)
	}
	if calls != 1 {
		t.Errorf("hook called %d times, want 1", calls)
	}
}

// TestClosingStreamNilHookIsSafe covers the onClose==nil branch.
func TestClosingStreamNilHookIsSafe(t *testing.T) {
	inner := &fakeStream{}
	s := &closingStream{Stream: inner}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.closes != 1 {
		t.Fatalf("inner Close called %d times, want 1", inner.closes)
	}
}
