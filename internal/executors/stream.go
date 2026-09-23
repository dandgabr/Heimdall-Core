package executors

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// DoStream implements contracts.Executor: one streaming call. A non-2xx upstream
// is returned here as an error (pre-commit); on 2xx the returned Stream is live
// and the caller owns Close.
//
// The Stream is bound to ctx: cancelling it cancels the upstream body read and
// makes Recv return a terminal error. The idle timeout is enforced per Recv.
func (e *Executor) DoStream(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	httpReq, err := e.buildRequest(ctx, req, cred)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := e.doer.Do(httpReq)
	if err != nil {
		return nil, transportError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, e.upstreamError(resp)
	}

	s := &sseStream{
		body:        resp.Body,
		headers:     resp.Header,
		ctx:         ctx,
		idleTimeout: e.cfg.IdleTimeout,
		scanner:     bufio.NewScanner(resp.Body),
	}
	s.scanner.Buffer(make([]byte, 0, 64<<10), maxSSEEventBytes)
	return s, nil
}

// sseStream decodes an SSE byte stream into application events. It is
// pull-based: Recv blocks until an event, a terminal error, or EOF, which is
// what makes backpressure natural and keeps memory bounded.
//
// CONCURRENCY MODEL (this is what the F2 deadlock fix is about):
//
//   - Recv is the SINGLE consumer path. It must never hold mu while scanning:
//     the read is blocking, and the idle watcher has to be able to close the
//     body from its own goroutine to interrupt that read. Holding mu across the
//     read (the previous bug) deadlocked the watcher against Recv forever.
//   - mu guards only short state transitions: the terminal outcome. It is never
//     held across a blocking call.
//   - closeOnce is the single gate for body.Close, so Close from any goroutine,
//     an idle expiry, and repeated calls cannot double-close the body.
//   - The watcher goroutine is JOINED by the stop function before readEvent
//     returns, so no timer can fire after Recv returned and no watcher leaks.
type sseStream struct {
	body        io.ReadCloser
	headers     http.Header
	ctx         context.Context
	idleTimeout time.Duration
	scanner     *bufio.Scanner

	// terminal, once set, is returned by every subsequent Recv. Guarded by mu.
	terminal error
	// closed reports that closeBody ran. Guarded by mu; set by closeBody and
	// read by readError, never held across the blocking read.
	closed bool
	// idleFired reports that the idle watcher, not Close, closed the body.
	// Guarded by mu; it lets readError classify the resulting read abort as a
	// timeout rather than a peer failure.
	idleFired bool
	// mu guards terminal, closed and idleFired (short transitions only). Never
	// held while reading from the body, and never held by closeBody around the
	// body.Close call itself beyond flipping the flags.
	mu sync.Mutex

	// closeOnce serialises body.Close across Recv, Close and the idle watcher.
	closeOnce sync.Once
	closeErr  error
}

var _ contracts.Stream = (*sseStream)(nil)

// Headers implements contracts.Stream.
func (s *sseStream) Headers() http.Header { return s.headers }

// Recv implements contracts.Stream. It returns io.EOF exactly once at a clean
// end and a *domain.DomainError on a mid-stream failure. After a terminal
// outcome every later call returns the same terminal outcome.
//
// Recv is not safe to call concurrently with itself (a Stream is a single
// pull consumer), but it IS safe against Close and against the idle watcher,
// which run on other goroutines.
func (s *sseStream) Recv() (contracts.Chunk, error) {
	// The terminal outcome is read under mu and the lock is released before
	// any blocking work; a watcher that closes the body meanwhile records the
	// terminal under the same mu, and Recv picks it up when the read unblocks.
	if term := s.terminalOutcome(); term != nil {
		return contracts.Chunk{}, term
	}

	// Read events until one is complete, the stream ends, or the context is
	// cancelled. Each event read is bounded by the idle timeout. No lock is
	// held here: the read blocks, and the idle watcher (or Close) must be free
	// to close the body to interrupt it.
	for {
		if err := s.ctx.Err(); err != nil {
			return contracts.Chunk{}, s.record(transportError(err))
		}

		event, id, data, ok, err := s.readEvent()
		if err != nil {
			return contracts.Chunk{}, s.record(err)
		}
		if !ok {
			// Clean EOF.
			return contracts.Chunk{}, s.record(io.EOF)
		}
		// A keep-alive comment yields an empty event with no data: skip it.
		if len(data) == 0 && event == "" && id == "" {
			continue
		}
		// The `[DONE]` sentinel is the TERMINATOR, not a chunk (D-01): consume
		// it and return a clean EOF so no consumer ever sees `[DONE]` as data.
		// The check is shared with the CloudCode decoder via contracts.IsSSEDone
		// so the two cannot diverge.
		if event == "" && contracts.IsSSEDone(data) {
			return contracts.Chunk{}, s.record(io.EOF)
		}
		return contracts.Chunk{Data: data, Event: event, ID: id}, nil
	}
}

// terminalOutcome reads the terminal outcome under mu (or nil when none is set).
func (s *sseStream) terminalOutcome() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal
}

// record makes err the terminal outcome and returns whichever outcome is now
// stored. It never overwrites an outcome already set: an idle expiry or an
// explicit Close that raced the read wins over the raw scanner error the close
// produced, which is what lets Recv distinguish a timeout/Close from a peer
// death.
func (s *sseStream) record(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal == nil {
		s.terminal = err
	}
	return s.terminal
}

// readEvent reads one SSE event delimited by a blank line. A field line is
// `field: value`; `data` lines are joined with newlines; `event` and `id` are
// taken verbatim. A comment line (`: ...`) is ignored but still forces the read
// that lets the idle timeout fire.
func (s *sseStream) readEvent() (event, id string, data []byte, ok bool, err error) {
	var dataLines [][]byte
	sawField := false

	// The idle budget applies to the whole event read: one watcher, armed once
	// and joined when this function returns. Scanning is blocking, so expiry
	// closes the body and unblocks the read with an error.
	if s.idleTimeout > 0 {
		stop := s.armIdleWatch()
		defer stop()
	}

	for {
		if err := s.ctx.Err(); err != nil {
			return "", "", nil, false, transportError(err)
		}

		if !s.scanner.Scan() {
			// Either a clean EOF or a read error. A read error that was caused
			// by the idle watcher or by Close is not a peer death: surface the
			// same typed timeout/cancellation a cancelled request would produce,
			// so Recv can never report a spurious bad_upstream/EOF.
			if err := s.scanner.Err(); err != nil {
				return "", "", nil, false, s.readError(err)
			}
			if len(dataLines) > 0 || sawField {
				return event, id, joinData(dataLines), true, nil
			}
			return "", "", nil, false, nil // EOF, no trailing event
		}
		line := s.scanner.Bytes()

		if len(line) == 0 {
			// Blank line: the event is complete (or a keep-alive with no fields).
			if !sawField {
				return "", "", nil, true, nil // empty event; caller skips
			}
			return event, id, joinData(dataLines), true, nil
		}
		sawField = true

		if line[0] == ':' {
			continue // comment / keep-alive
		}

		field, value := splitField(line)
		switch field {
		case "event":
			event = value
		case "id":
			id = value
		case "data":
			dataLines = append(dataLines, []byte(value))
		default:
			// Unknown field: ignored per the SSE spec.
		}
	}
}

// armIdleWatch starts a watcher that closes the body if the current event read
// exceeds the idle budget. The returned stop cancels the timer AND waits for
// the watcher goroutine to finish, so:
//
//   - stop() is safe to call twice (a closed channel is never closed again);
//   - the timer can never fire after readEvent returned (no reuse of state);
//   - no watcher goroutine leaks.
//
// Closing the body is what interrupts the blocking scan; crucially, it does NOT
// touch the Recv mutex, so the watcher cannot deadlock against Recv.
func (s *sseStream) armIdleWatch() func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	timer := time.NewTimer(s.idleTimeout)
	go func() {
		defer close(stopped)
		select {
		case <-timer.C:
			s.mu.Lock()
			s.idleFired = true
			s.mu.Unlock()
			_ = s.closeBody()
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			timer.Stop()
			close(done)
			<-stopped // join the watcher so it cannot outlive readEvent
		})
	}
}

// readError classifies a scanner error: when the body was closed by the idle
// watcher or by Close, the resulting read error is our own abort, not a peer
// failure. The idle expiry maps to a retryable upstream_timeout and a caller
// Close to the cancellation error, so Recv never reports a spurious
// bad_upstream for either.
func (s *sseStream) readError(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idleFired {
		return transportError(errIdleTimeout)
	}
	if s.closed {
		return transportError(context.Canceled)
	}
	return transportError(err)
}

// closeBody closes the body exactly once, from any goroutine (Recv's idle
// watcher, Close, or a caller). It uses closeOnce, NOT the Recv mutex, so it can
// never block behind a Recv that is holding mu.
func (s *sseStream) closeBody() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.closeErr = s.body.Close()
	})
	return s.closeErr
}

// Close implements contracts.Stream: idempotent and safe from any goroutine.
func (s *sseStream) Close() error {
	return s.closeBody()
}

// splitField parses an SSE field line into name and value, trimming one leading
// space from the value.
func splitField(line []byte) (field, value string) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return string(line), ""
	}
	value = string(line[i+1:])
	value = strings.TrimPrefix(value, " ")
	return string(line[:i]), value
}

// joinData concatenates data lines with a newline, per the SSE spec.
func joinData(lines [][]byte) []byte {
	return bytes.Join(lines, []byte("\n"))
}
