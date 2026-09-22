package passthrough

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// contains is a local alias so the assertions read uniformly.
func contains(h, n string) bool { return strings.Contains(h, n) }

// TestTransportErrorBranches covers transportError's three branches directly.
func TestTransportErrorBranches(t *testing.T) {
	if got := transportError(nil); got != nil {
		t.Errorf("transportError(nil) = %v, want nil", got)
	}

	// Context cancellation -> timeout.
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		de := transportError(err)
		if de.Code != domain.CodeUpstreamTimeout || de.HTTPStatus != http.StatusGatewayTimeout {
			t.Errorf("transportError(%v) = %+v", err, de)
		}
	}

	// A net.Error with Timeout() -> timeout.
	de := transportError(timeoutNetError{})
	if de.Code != domain.CodeUpstreamTimeout {
		t.Errorf("timeout net error = %+v", de)
	}

	// Any other error -> unavailable/502.
	de = transportError(errors.New("boom"))
	if de.Code != domain.CodeUpstreamUnavailable || de.HTTPStatus != http.StatusBadGateway {
		t.Errorf("generic error = %+v", de)
	}
}

// TestUpstreamErrorAllStatuses covers each status branch of upstreamError.
func TestUpstreamErrorAllStatuses(t *testing.T) {
	tests := []struct {
		status    int
		wantCode  string
		wantRetry bool
	}{
		{http.StatusTooManyRequests, domain.CodeUpstreamUnavailable, true},
		{http.StatusRequestTimeout, domain.CodeUpstreamTimeout, true},
		{http.StatusGatewayTimeout, domain.CodeUpstreamTimeout, true},
		{http.StatusUnauthorized, domain.CodeUpstreamUnavailable, false},
		{http.StatusForbidden, domain.CodeUpstreamUnavailable, false},
		{http.StatusBadRequest, domain.CodeUpstreamUnavailable, false},
	}
	for _, tt := range tests {
		resp := &http.Response{
			StatusCode: tt.status,
			Body:       http.NoBody,
		}
		de := upstreamError(resp)
		if de.Code != tt.wantCode || de.Retryable != tt.wantRetry {
			t.Errorf("status %d: code=%s retry=%v, want %s/%v",
				tt.status, de.Code, de.Retryable, tt.wantCode, tt.wantRetry)
		}
	}
}

// TestWriteSSEError covers the in-band error writer (0% before).
func TestWriteSSEError(t *testing.T) {
	// With a flusher.
	rec := httptest.NewRecorder()
	writeSSEError(rec, rec, domain.New(domain.CodeUpstreamUnavailable))
	body := rec.Body.String()
	if !contains(body, "event: error") || !contains(body, domain.CodeUpstreamUnavailable) {
		t.Errorf("SSE error body = %q", body)
	}
	if !rec.Flushed {
		t.Error("SSE error did not flush")
	}

	// With a nil flusher: must not panic.
	rec2 := httptest.NewRecorder()
	writeSSEError(rec2, nil, domain.New(domain.CodeUpstreamUnavailable))
	if !contains(rec2.Body.String(), "event: error") {
		t.Errorf("SSE error with nil flusher = %q", rec2.Body.String())
	}
}

// TestStreamPostCommitErrorEmitsSSEError drives Stream's in-band error path: the
// upstream returns 200 then fails mid-stream, so the failure must arrive as an
// SSE event, not a status change.
func TestStreamPostCommitErrorEmitsSSEError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		// Abort the connection: the client sees a read error post-commit.
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	rec := httptest.NewRecorder()
	result, err := client.Stream(context.Background(), []byte(`{"stream":true}`), rec)
	if err != nil {
		t.Fatalf("Stream returned an HTTP error post-commit: %v", err)
	}
	if !result.Committed {
		t.Fatal("stream was not committed")
	}
	if !contains(rec.Body.String(), "event: error") {
		t.Errorf("post-commit failure not signalled in-band: %q", rec.Body.String())
	}
}

// failingWriter is an http.ResponseWriter whose Write always fails, modelling a
// client that disconnected mid-stream.
type failingWriter struct {
	header http.Header
}

func (f *failingWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *failingWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }
func (f *failingWriter) WriteHeader(int)           {}

// TestStreamStopsOnDownstreamWriteFailure covers the writeErr branch: a client
// that disconnects must end the relay without panicking.
func TestStreamStopsOnDownstreamWriteFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, line := range []string{"data: a\n\n", "data: b\n\n"} {
			_, _ = w.Write([]byte(line))
			flusher.Flush()
		}
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	result, err := client.Stream(context.Background(), []byte(`{"stream":true}`), &failingWriter{})
	if err != nil {
		t.Fatalf("Stream returned an HTTP error after commit: %v", err)
	}
	if !result.Committed {
		t.Error("stream should be committed once the 200 was written")
	}
}

// TestCompleteRequestBuildError covers Complete's newRequest-error branch.
func TestCompleteRequestBuildError(t *testing.T) {
	c := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1/v1"})
	c.baseURL = "http://exa mple.test/v1" // invalid, so newRequest fails
	if _, err := c.Complete(context.Background(), []byte("{}")); err == nil {
		t.Fatal("Complete succeeded with an invalid URL")
	}
}

// TestStreamRequestBuildError covers Stream's newRequest-error branch.
func TestStreamRequestBuildError(t *testing.T) {
	c := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1/v1"})
	c.baseURL = "http://exa mple.test/v1"
	rec := httptest.NewRecorder()
	if _, err := c.Stream(context.Background(), []byte("{}"), rec); err == nil {
		t.Fatal("Stream succeeded with an invalid URL")
	}
}

// TestStreamTransportError covers Stream's http.Do-error branch with a failing
// transport.
func TestStreamTransportError(t *testing.T) {
	c := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1/v1"})
	c.http = &http.Client{Transport: failingRoundTripper{}}
	rec := httptest.NewRecorder()
	if _, err := c.Stream(context.Background(), []byte("{}"), rec); err == nil {
		t.Fatal("Stream succeeded with a failing transport")
	}
}

// TestCompleteTransportError covers Complete's Do-error branch.
func TestCompleteTransportError(t *testing.T) {
	c := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1/v1"})
	c.http = &http.Client{Transport: failingRoundTripper{}}
	if _, err := c.Complete(context.Background(), []byte("{}")); err == nil {
		t.Fatal("Complete succeeded with a failing transport")
	}
}

// failingRoundTripper always errors.
type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport down")
}

// TestHandlerStreamPreCommitError covers the handler's stream-error branch: the
// upstream refuses before commit, so the handler writes an HTTP error.
func TestHandlerStreamPreCommitError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer upstream.Close()

	client := mustClient(t, ClientConfig{BaseURL: upstream.URL})
	mux := http.NewServeMux()
	NewHandler(client).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// TestStreamNon2xxIsNotCommitted covers the upstream-error-before-commit branch.
func TestStreamNon2xxIsNotCommitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	rec := httptest.NewRecorder()
	result, err := client.Stream(context.Background(), []byte(`{"stream":true}`), rec)
	if err == nil {
		t.Fatal("upstream 502 accepted")
	}
	if result.Committed {
		t.Error("stream committed on a pre-body upstream error")
	}
}

// TestNewRequestBuildError covers newRequest's error branch: a base URL with a
// control character makes http.NewRequestWithContext fail. newRequest sets the
// Authorization header only when an API key is configured, so this also pins
// that an empty key omits the header.
func TestNewRequestBuildError(t *testing.T) {
	// Build a valid client, then corrupt its base URL so newRequest's own error
	// branch is exercised (NewClient would have refused the bad URL earlier).
	c := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1/v1"})
	c.baseURL = "http://exa mple.test/v1"
	if _, err := c.newRequest(context.Background(), []byte("{}")); err == nil {
		t.Fatal("invalid base URL accepted")
	}

	// No API key -> no Authorization header.
	ok := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1"})
	req, err := ok.newRequest(context.Background(), []byte("{}"))
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("Authorization set without an API key")
	}
}

// TestCompleteReadError covers Complete's body-read error branch via a server
// that closes mid-body.
func TestCompleteReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		hj := w.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	if _, err := client.Complete(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("truncated body accepted")
	}
}

// timeoutNetError is a net.Error whose Timeout reports true.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

var _ net.Error = timeoutNetError{}

// TestStreamCancelledContextMidStream covers the main-loop ctx.Done branch and
// the pump cancellation: the server emits one chunk, the client cancels, and the
// relay must stop without writing a second chunk.
func TestStreamCancelledContextMidStream(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		// Block until the client cancels, then try to write more (the read side
		// is gone).
		<-release
		_, _ = w.Write([]byte("data: second\n\n"))
		flusher.Flush()
	}))
	defer srv.Close()
	defer close(release)

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), rec)
		close(done)
	}()
	// Let the first chunk arrive, then cancel.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return after cancellation")
	}
	if !strings.Contains(rec.Body.String(), "first") {
		t.Errorf("first chunk not relayed: %q", rec.Body.String())
	}
}

// blockingWriter blocks on every Write until released, so the relay's main loop
// stalls, the bounded chunk buffer fills, and the reader goroutine blocks on
// send. Cancelling then drives the reader's pumpCtx.Done send-branch.
type blockingWriter struct {
	header  http.Header
	release chan struct{}
}

func (b *blockingWriter) Header() http.Header {
	if b.header == nil {
		b.header = http.Header{}
	}
	return b.header
}
func (b *blockingWriter) WriteHeader(int) {}
func (b *blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// TestStreamReaderPumpCancelBranch covers the reader goroutine's pumpCtx.Done
// branch (stream.go ~L104): the downstream blocks, the buffer fills, and a
// cancel releases the blocked send.
func TestStreamReaderPumpCancelBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		// Emit more chunks than the buffer holds so the reader blocks on send.
		for i := 0; i < streamBufferSize+8; i++ {
			_, _ = w.Write([]byte("data: chunk\n\n"))
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	w := &blockingWriter{release: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), w)
		close(done)
	}()

	// Give the reader time to fill the buffer, then cancel; release the writer
	// so the handler's Write returns and the test can finish.
	time.Sleep(80 * time.Millisecond)
	cancel()
	close(w.release)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return after cancellation")
	}
}

// scriptedBody is an io.ReadCloser whose behavior is driven by a script, letting
// a test control exactly when reads succeed, fail, or block — the seam needed to
// reach the reader goroutine's cancel branches deterministically.
type scriptedBody struct {
	// chunks yields this many successful single-byte reads, then blocks on gate.
	chunks int
	gate   chan struct{}
	// failAfter, when true, makes the read after chunks return an error instead
	// of blocking.
	failAfter bool
	closed    chan struct{}
	once      sync.Once
}

func (b *scriptedBody) Read(p []byte) (int, error) {
	if b.chunks > 0 {
		b.chunks--
		p[0] = 'x'
		return 1, nil
	}
	if b.failAfter {
		return 0, errors.New("scripted read failure")
	}
	<-b.gate
	return 0, io.EOF
}

func (b *scriptedBody) Close() error {
	b.once.Do(func() {
		if b.closed != nil {
			close(b.closed)
		}
	})
	return nil
}

// bodyRoundTripper returns a fixed 200 SSE response whose body is supplied by
// the test (any io.ReadCloser, so different scripted bodies can be used).
type bodyRoundTripper struct{ body io.ReadCloser }

func (rt bodyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       rt.body,
	}, nil
}

// TestStreamReaderTopOfLoopCancel covers the reader's top-of-loop pumpCtx check
// (stream.go L92-93): the body yields many fast chunks so the reader spins, and a
// cancel is observed on a loop iteration.
func TestStreamReaderTopOfLoopCancel(t *testing.T) {
	body := &scriptedBody{chunks: 1_000_000, gate: make(chan struct{}), closed: make(chan struct{})}
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"})
	client.http = &http.Client{Transport: bodyRoundTripper{body: body}}

	// A writer that drains slowly so the reader is not permanently blocked.
	ctx, cancel := context.WithCancel(context.Background())
	w := &discardWriter{}
	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), w)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return after cancellation")
	}
}

// TestStreamReaderErrorSendCancel covers the reader goroutine's error-send
// cancel branch (stream.go L113): the buffer fills (slow writer), then a read
// error arrives after cancellation.
func TestStreamReaderErrorSendCancel(t *testing.T) {
	body := &scriptedBody{chunks: streamBufferSize * 4, failAfter: true, gate: make(chan struct{}), closed: make(chan struct{})}
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"})
	client.http = &http.Client{Transport: bodyRoundTripper{body: body}}

	ctx, cancel := context.WithCancel(context.Background())
	w := &blockingWriter{release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), w)
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	cancel()
	close(w.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return")
	}
}

// discardWriter accepts every byte immediately.
type discardWriter struct{ header http.Header }

func (d *discardWriter) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}
func (d *discardWriter) WriteHeader(int)             {}
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestStreamReaderErrorSendCancelled covers stream.go's error-send select taking
// the pumpCtx.Done() arm (the block the Probe flagged). The body yields EXACTLY
// streamBufferSize chunks so the buffer fills without the reader ever blocking on
// a DATA send, then the next read errors. With the buffer still full (the main
// loop is behind a blocking writer), the error send cannot proceed, so a cancel
// forces the Done arm.
func TestStreamReaderErrorSendCancelled(t *testing.T) {
	body := &scriptedBody{
		chunks:    streamBufferSize, // exactly fills the buffer
		failAfter: true,             // the next read returns a non-EOF error
		gate:      make(chan struct{}),
		closed:    make(chan struct{}),
	}
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"})
	client.http = &http.Client{Transport: bodyRoundTripper{body: body}}

	ctx, cancel := context.WithCancel(context.Background())
	w := &blockingWriter{release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), w)
		close(done)
	}()

	// Give the reader time to fill the buffer and reach the error send.
	time.Sleep(80 * time.Millisecond)
	cancel()
	close(w.release)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return")
	}
}

// gateBody lets a test drive the reader goroutine exactly: it yields `yield`
// single-byte reads, then blocks on `gate`; when released it returns the canned
// `then` result once, so the loop reaches its next top-of-loop check
// deterministically.
type gateBody struct {
	yield int
	gate  chan struct{}
	thenN int
	thenE error
}

func (b *gateBody) Read(p []byte) (int, error) {
	if b.yield > 0 {
		b.yield--
		p[0] = 'y'
		return 1, nil
	}
	if b.gate != nil {
		<-b.gate
		b.gate = nil // release only once
		return b.thenN, b.thenE
	}
	return b.thenN, b.thenE
}

func (b *gateBody) Close() error { return nil }

// TestStreamReaderTopOfLoopCheckDeterministic covers stream.go's top-of-loop
// `pumpCtx.Err()` return (L92-93) deterministically: the body yields one chunk,
// blocks, and on release returns (0, nil) so the loop goes back to the top AFTER
// the context is cancelled and returns there.
func TestStreamReaderTopOfLoopCheckDeterministic(t *testing.T) {
	gate := make(chan struct{})
	body := &gateBody{yield: 1, gate: gate}
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"})
	client.http = &http.Client{Transport: bodyRoundTripper{body: body}}

	ctx, cancel := context.WithCancel(context.Background())
	w := &discardWriter{}
	done := make(chan struct{})
	go func() {
		_, _ = client.Stream(ctx, []byte(`{"stream":true}`), w)
		close(done)
	}()

	// Let the reader yield its one chunk and block on the gate, then cancel and
	// release the body so the next loop iteration sees the cancellation.
	time.Sleep(30 * time.Millisecond)
	cancel()
	close(gate)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return")
	}
}

// syncBody is designed to reach the reader goroutine's error-send cancel arm
// deterministically. It yields exactly bufSize+1 single-byte chunks (one more
// than the channel holds), then returns a terminal error. On the error read it
// closes errRead, which is the precise instant the channel is known to be full:
// the reader can only have reached the error read after ALL of its data sends
// completed, and the parked writer ensures none were drained.
type syncBody struct {
	remaining int
	errRead   chan struct{}
	once      sync.Once
}

func (b *syncBody) Read(p []byte) (int, error) {
	if b.remaining > 0 {
		b.remaining--
		p[0] = 's'
		return 1, nil
	}
	b.once.Do(func() { close(b.errRead) })
	return 0, errors.New("sync read failure")
}

func (b *syncBody) Close() error { return nil }

// parkedWriter signals the first Write and then blocks until released, so the
// main relay loop consumes exactly one chunk and parks — guaranteeing the chunk
// channel cannot drain and stays full once the reader has produced its chunks.
type parkedWriter struct {
	header  http.Header
	parked  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *parkedWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *parkedWriter) WriteHeader(int) {}
func (w *parkedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.parked) })
	<-w.release
	return len(p), nil
}

// TestStreamErrorSendCancelDeterministic covers stream.go's error-send select
// taking the pumpCtx.Done() arm (the `return` the Probe flagged). It is
// deterministic: it waits for the writer to park (exactly one chunk consumed)
// and for the body's error read (all chunks produced), at which point the
// channel is provably full; only then does it cancel, so the error send cannot
// proceed and the Done arm MUST run. No sleep is used for correctness.
func TestStreamErrorSendCancelDeterministic(t *testing.T) {
	body := &syncBody{remaining: streamBufferSize + 1, errRead: make(chan struct{})}
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"})
	client.http = &http.Client{Transport: bodyRoundTripper{body: body}}

	w := &parkedWriter{parked: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		res StreamResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := client.Stream(ctx, []byte(`{"stream":true}`), w)
		done <- result{res, err}
	}()

	// 1. The writer has consumed exactly one chunk and is parked; nothing drains.
	select {
	case <-w.parked:
	case <-time.After(3 * time.Second):
		t.Fatal("writer never parked")
	}
	// 2. The reader has produced all chunks and is at the error read; the channel
	//    is provably full now, so the error send cannot complete.
	select {
	case <-body.errRead:
	case <-time.After(3 * time.Second):
		t.Fatal("body never reached its terminal read")
	}
	// 3. Cancel while the error send is blocked: only Done is ready.
	cancel()
	close(w.release)

	select {
	case got := <-done:
		// The stream was committed (the upstream answered 200) and ended without
		// a panic; cancellation after commit is a clean stop.
		if !got.res.Committed {
			t.Errorf("expected the stream to be committed before cancellation")
		}
		if got.err != nil {
			t.Errorf("Stream returned %v, want nil after a post-commit cancel", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not return after cancellation")
	}
}
