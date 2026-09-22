package executors

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// blockingBody is a body whose Read blocks until Close is called and then fails,
// mimicking net/http's behaviour when a response body is closed under a blocked
// read. It lets the stream tests drive the idle/Close paths with no network.
type blockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingBody() *blockingBody { return &blockingBody{closed: make(chan struct{})} }

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("read on closed body")
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func newBlockingStream(idle time.Duration) (*sseStream, *blockingBody) {
	b := newBlockingBody()
	s := &sseStream{
		body:        b,
		headers:     http.Header{},
		ctx:         context.Background(),
		idleTimeout: idle,
		scanner:     bufio.NewScanner(b),
	}
	s.scanner.Buffer(make([]byte, 0, 64<<10), maxSSEEventBytes)
	return s, b
}

// waitGoroutinesAtMost polls until the live goroutine count is at or below want,
// or the deadline passes, and returns the last observed count.
func waitGoroutinesAtMost(want int, deadline time.Duration) int {
	end := time.Now().Add(deadline)
	got := runtime.NumGoroutine()
	for got > want && time.Now().Before(end) {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
		got = runtime.NumGoroutine()
	}
	return got
}

// streamServer returns an httptest server that emits the given SSE frames and
// then ends (or blocks, when block is true).
func streamServer(t *testing.T, frames []string, block bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, f := range frames {
			_, _ = w.Write([]byte(f))
			flusher.Flush()
		}
		if block {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// loopbackExecutor builds an executor whose transport is the REAL egress policy,
// pointed at the loopback httptest server. It is how the stream tests exercise
// the actual TCP + SSE path.
func loopbackExecutor(t *testing.T, srv *httptest.Server, idle time.Duration) *Executor {
	t.Helper()
	cfg := Config{Family: "z.ai", BaseURL: srv.URL, AllowLoopback: true, IdleTimeout: idle}
	deps := realEgressDeps("k")
	e, err := New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// TestDoStreamDecodesSSEEvents covers the frame decoding: multi-line data is
// joined, event and id are preserved, and a comment is skipped.
func TestDoStreamDecodesSSEEvents(t *testing.T) {
	srv := streamServer(t, []string{
		": keep-alive\n\n",
		"event: message\nid: 7\ndata: {\"a\":1}\n\n",
		"data: line1\ndata: line2\n\n",
		"data: [DONE]\n\n",
	}, false)
	e := loopbackExecutor(t, srv, 0)

	stream, err := e.DoStream(context.Background(), contracts.WireRequest{Body: []byte(`{"stream":true}`)}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	if stream.Headers().Get("Content-Type") != "text/event-stream" {
		t.Errorf("headers not exposed: %v", stream.Headers())
	}

	var got []contracts.Chunk
	for {
		ch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		got = append(got, ch)
	}
	if len(got) != 3 {
		t.Fatalf("chunks = %d, want 3 (comment skipped): %+v", len(got), got)
	}
	if got[0].Event != "message" || got[0].ID != "7" || string(got[0].Data) != `{"a":1}` {
		t.Errorf("chunk0 = %+v", got[0])
	}
	if string(got[1].Data) != "line1\nline2" {
		t.Errorf("multi-line data = %q", got[1].Data)
	}
	if string(got[2].Data) != "[DONE]" {
		t.Errorf("chunk2 = %q", got[2].Data)
	}
}

// TestRecvIsTerminalAfterEOF pins invariant 6: after EOF every later Recv returns
// the same terminal outcome.
func TestRecvIsTerminalAfterEOF(t *testing.T) {
	srv := streamServer(t, []string{"data: x\n\n"}, false)
	e := loopbackExecutor(t, srv, 0)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("third Recv = %v, want EOF (terminal)", err)
	}
}

// TestDoStreamNon2xxIsPreCommitError pins invariant 3's precondition: a non-2xx
// is returned by DoStream as an error, never as a live stream.
func TestDoStreamNon2xxIsPreCommitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream boom"))
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 0)
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred()); err == nil {
		t.Fatal("expected a pre-commit error")
	} else if !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestStreamCancelTerminatesRecv covers invariant 5: cancelling the DoStream
// context makes Recv return a terminal typed error.
func TestStreamCancelTerminatesRecv(t *testing.T) {
	srv := streamServer(t, []string{"data: first\n\n"}, true)
	e := loopbackExecutor(t, srv, 0)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := e.DoStream(ctx, contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	cancel()
	// Recv must return a terminal error (not block forever). Give it a bound so a
	// regression fails rather than hangs.
	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || err == io.EOF {
			t.Fatalf("Recv after cancel = %v, want a typed error", err)
		}
		if _, ok := err.(*domain.DomainError); !ok {
			t.Fatalf("Recv after cancel = %T, want *DomainError", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Recv did not return after cancel")
	}
}

// TestStreamMidDeathEmitsTerminalError covers a stream that dies mid-way: an
// event is delivered, then Recv returns a typed error (never a silent EOF).
func TestStreamMidDeathEmitsTerminalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		// Abort the connection.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 0)

	stream, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	// The next Recv sees the aborted body: a typed error, not EOF.
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected an error after a mid-stream death")
	}
	if err == io.EOF {
		t.Fatal("a mid-stream death must not be reported as a clean EOF")
	}
	if _, ok := err.(*domain.DomainError); !ok {
		t.Fatalf("err = %T, want *DomainError", err)
	}
}

// TestStreamIdleTimeout covers the idle budget: a stream that sends one event
// then stalls beyond the idle timeout makes Recv return a terminal error.
func TestStreamIdleTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		<-release // stall
	}))
	defer srv.Close()
	defer close(release)

	e := loopbackExecutor(t, srv, 50*time.Millisecond)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	_, err = stream.Recv()
	if err == nil || err == io.EOF {
		t.Fatalf("idle Recv = %v, want a terminal error", err)
	}
}

// TestStreamCloseIsIdempotentAndSafe covers invariant 5's Close guarantee.
func TestStreamCloseIsIdempotentAndSafe(t *testing.T) {
	srv := streamServer(t, []string{"data: x\n\n"}, true)
	e := loopbackExecutor(t, srv, 0)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	// Close from several goroutines must not race or panic.
	var done int32
	for i := 0; i < 4; i++ {
		go func() {
			_ = stream.Close()
			atomic.AddInt32(&done, 1)
		}()
	}
	for atomic.LoadInt32(&done) < 4 {
		time.Sleep(time.Millisecond)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
}

// TestStreamSlowButComplete covers a stream with pauses shorter than the idle
// budget: all events arrive.
func TestStreamSlowButComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			time.Sleep(5 * time.Millisecond)
			_, _ = w.Write([]byte("data: x\n\n"))
			flusher.Flush()
		}
	}))
	defer srv.Close()
	e := loopbackExecutor(t, srv, 500*time.Millisecond)
	stream, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	n := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("chunks = %d, want 3", n)
	}
}

// TestDoStreamBuildError covers DoStream's pre-request error.
func TestDoStreamBuildError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z", BaseURL: "http://exa mple.test/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k"))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred()); err == nil {
		t.Fatal("expected a build error")
	}
}

// TestDoStreamTransportError covers DoStream's transport failure.
func TestDoStreamTransportError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }), "k"))
	if _, err := e.DoStream(context.Background(), contracts.WireRequest{}, apiKeyCred()); err == nil {
		t.Fatal("expected a transport error")
	}
}

// TestSSEFieldParsing covers the field splitter and data joiner directly.
func TestSSEFieldParsing(t *testing.T) {
	tests := map[string][2]string{
		"data: value": {"data", "value"},
		"data:value":  {"data", "value"},
		"event: x":    {"event", "x"},
		"nofield":     {"nofield", ""},
		"id: 42":      {"id", "42"},
		"data:  two":  {"data", " two"},
	}
	for line, want := range tests {
		f, v := splitField([]byte(line))
		if f != want[0] || v != want[1] {
			t.Errorf("splitField(%q) = %q,%q want %q,%q", line, f, v, want[0], want[1])
		}
	}
	if got := string(joinData([][]byte{[]byte("a"), []byte("b")})); got != "a\nb" {
		t.Errorf("joinData = %q", got)
	}
	var _ = strings.TrimSpace
}

// TestStreamIdleTimeoutNoGoroutineLeak is the regression guard for the F2
// deadlock: the idle watcher must terminate, close the body and be joined, so
// Recv returns a typed upstream_timeout and no goroutine leaks. Before the fix
// the watcher deadlocked on Recv's mutex and leaked forever.
func TestStreamIdleTimeoutNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	s, body := newBlockingStream(30 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := s.Recv()
		done <- err
	}()

	select {
	case err := <-done:
		if !hasCode(err, domain.CodeUpstreamTimeout) {
			t.Fatalf("idle Recv = %v, want %s", err, domain.CodeUpstreamTimeout)
		}
		de, ok := err.(*domain.DomainError)
		if !ok || !de.Retryable || de.Scope != domain.ScopeProvider {
			t.Fatalf("idle Recv = %+v, want retryable provider scope", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Recv did not return on idle timeout (deadlock regressed)")
	}

	select {
	case <-body.closed:
	default:
		t.Fatal("idle watcher did not close the body")
	}

	// The watcher goroutine must have exited: the count returns to base.
	if got := waitGoroutinesAtMost(base, 2*time.Second); got > base {
		t.Fatalf("goroutine leak: %d live, want <= %d", got, base)
	}

	// A second Recv is terminal and needs no extra goroutine.
	if _, err := s.Recv(); !hasCode(err, domain.CodeUpstreamTimeout) {
		t.Fatalf("terminal Recv = %v, want the recorded timeout", err)
	}
	if got := waitGoroutinesAtMost(base, 2*time.Second); got > base {
		t.Fatalf("goroutine leak after terminal Recv: %d live, want <= %d", got, base)
	}
}

// TestStreamCloseUnblocksRecvNoLeak covers Close racing a blocked Recv: Close
// closes the body without the Recv lock, Recv returns a typed cancellation, and
// both the watcher and the read goroutine finish.
func TestStreamCloseUnblocksRecvNoLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	s, body := newBlockingStream(time.Hour) // idle cannot fire; Close is the trigger
	done := make(chan error, 1)
	go func() {
		_, err := s.Recv()
		done <- err
	}()

	// Give Recv a moment to enter the blocking read, then Close from here.
	time.Sleep(20 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !hasCode(err, domain.CodeUpstreamTimeout) {
			t.Fatalf("Recv after Close = %v, want a typed error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Recv")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("Close did not close the body")
	}
	if got := waitGoroutinesAtMost(base, 2*time.Second); got > base {
		t.Fatalf("goroutine leak: %d live, want <= %d", got, base)
	}
}

// TestStreamStopIsIdempotentAndJoined covers the arm/stop contract: calling the
// returned stop twice must not panic (a double close(done) regression) and the
// timer must not fire after stop returned.
func TestStreamStopIsIdempotentAndJoined(t *testing.T) {
	s, body := newBlockingStream(25 * time.Millisecond)
	stop := s.armIdleWatch()
	stop()
	stop() // must be a no-op, not a panic

	// After a joined stop, waiting past the idle budget must NOT close the body.
	time.Sleep(60 * time.Millisecond)
	select {
	case <-body.closed:
		t.Fatal("timer fired after stop returned")
	default:
	}
}

// TestStreamRecvConcurrentClose is the -race probe: Recv and Close run together
// on many streams; the outcome is always a typed error and never a panic.
func TestStreamRecvConcurrentClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, _ := newBlockingStream(time.Hour)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := s.Recv()
			if err == nil || err == io.EOF {
				t.Errorf("Recv = %v, want a typed error", err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = s.Close()
			_ = s.Close()
		}()
		wg.Wait()
	}
}

// TestStreamReadErrorClassification drives readError directly for the three
// classifications: peer death, idle abort and caller Close.
func TestStreamReadErrorClassification(t *testing.T) {
	peer, _ := newBlockingStream(0)
	if err := peer.readError(errors.New("connection reset")); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("peer read error = %v, want %s", err, domain.CodeUpstreamUnavailable)
	}

	idle, _ := newBlockingStream(0)
	idle.mu.Lock()
	idle.idleFired = true
	idle.closed = true
	idle.mu.Unlock()
	if err := idle.readError(errors.New("closed")); !hasCode(err, domain.CodeUpstreamTimeout) {
		t.Fatalf("idle read error = %v, want %s", err, domain.CodeUpstreamTimeout)
	}

	closed, _ := newBlockingStream(0)
	closed.mu.Lock()
	closed.closed = true
	closed.mu.Unlock()
	if err := closed.readError(errors.New("closed")); !hasCode(err, domain.CodeUpstreamTimeout) {
		t.Fatalf("closed read error = %v, want %s", err, domain.CodeUpstreamTimeout)
	}
}

// newScannerStream builds an idle-free stream over in-memory SSE text, so
// readEvent can be driven directly for the remaining branches.
func newScannerStream(text string) *sseStream {
	r := strings.NewReader(text)
	return &sseStream{
		body:    io.NopCloser(r),
		headers: http.Header{},
		ctx:     context.Background(),
		scanner: bufio.NewScanner(strings.NewReader(text)),
	}
}

// TestReadEventBranches drives readEvent directly for the branches the
// end-to-end SSE tests do not reach: an unknown field line, a bare empty event,
// and a context cancelled before the scan begins.
func TestReadEventBranches(t *testing.T) {
	// Unknown field: ignored per the SSE spec, the data line still completes.
	s := newScannerStream("x-unknown: 1\ndata: d\n\n")
	event, id, data, ok, err := s.readEvent()
	if err != nil || !ok || string(data) != "d" || event != "" || id != "" {
		t.Fatalf("unknown field: %q %q %q %v %v", event, id, data, ok, err)
	}

	// A bare blank line is an empty event with ok=true (Recv skips it).
	s2 := newScannerStream("\n\n")
	ev, i2, d2, ok2, err2 := s2.readEvent()
	if err2 != nil || !ok2 || d2 != nil || ev != "" || i2 != "" {
		t.Fatalf("empty event: %q %q %q %v %v", ev, i2, d2, ok2, err2)
	}

	// A context cancelled before the scan returns a typed error, not EOF.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s3 := newScannerStream("data: x\n\n")
	s3.ctx = ctx
	if _, _, _, _, err := s3.readEvent(); !hasCode(err, domain.CodeUpstreamTimeout) {
		t.Fatalf("cancelled readEvent = %v, want %s", err, domain.CodeUpstreamTimeout)
	}
}

// TestIdleTimeoutSentinelClassification covers transportError's explicit
// errIdleTimeout branch: an idle stall is retryable and provider-scoped.
func TestIdleTimeoutSentinelClassification(t *testing.T) {
	de := transportError(errIdleTimeout)
	if de == nil || de.Code != domain.CodeUpstreamTimeout || !de.Retryable || de.Scope != domain.ScopeProvider {
		t.Fatalf("transportError(errIdleTimeout) = %+v", de)
	}
	if errIdleTimeout.Error() == "" {
		t.Fatal("sentinel message is empty")
	}
}

// TestStreamCleanEOFTerminalWithoutPending covers the tail of readEvent: a
// scanner at clean EOF returns ok=false and Recv records io.EOF.
func TestStreamCleanEOFTerminal(t *testing.T) {
	s := &sseStream{
		body:    io.NopCloser(strings.NewReader("")),
		headers: http.Header{},
		ctx:     context.Background(),
		scanner: bufio.NewScanner(strings.NewReader("")),
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("Recv = %v, want EOF", err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("terminal Recv = %v, want EOF", err)
	}
	_ = s.Close()
}

// TestStreamTrailingEventWithoutBlankLine covers readEvent's EOF-with-fields
// branch: a final event not followed by a blank line is still delivered.
func TestStreamTrailingEventWithoutBlankLine(t *testing.T) {
	s := &sseStream{
		body:    io.NopCloser(strings.NewReader("data: tail")),
		headers: http.Header{},
		ctx:     context.Background(),
		scanner: bufio.NewScanner(strings.NewReader("data: tail")),
	}
	ch, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(ch.Data) != "tail" {
		t.Fatalf("data = %q, want tail", ch.Data)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("second Recv = %v, want EOF", err)
	}
}

// TestStreamCloseAfterCleanEOFReturnsStoredErr covers Close being called after a
// terminal outcome and returning the stored close error (nil for the fake).
func TestStreamCloseAfterCleanEOFReturnsStoredErr(t *testing.T) {
	b := newBlockingBody()
	if err := b.Close(); err != nil {
		t.Fatalf("fake close: %v", err)
	}
	s := &sseStream{body: b, headers: http.Header{}, ctx: context.Background(), scanner: bufio.NewScanner(b)}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
