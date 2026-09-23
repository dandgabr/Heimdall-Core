package cloudcode

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// maxStreamEventBytes bounds a single SSE line, so a hostile frame cannot grow
// memory without bound.
const maxStreamEventBytes = 1 << 20 // 1 MiB

// sseStream decodes the CloudCode streamGenerateContent SSE into canonical
// chunks. Each `data:` line is a CloudCode frame ({"response": {...}}), unwrapped
// to the Gemini payload and translated to canonical, then uncloaked.
//
// CONCURRENCY: Recv never holds mu across the blocking scan; the idle watcher
// closes the body via closeOnce (never the Recv mutex), and stop() joins the
// watcher. This is the same deadlock-free model as the OpenAI executor's stream.
type sseStream struct {
	body        io.ReadCloser
	headers     http.Header
	ctx         context.Context
	idleTimeout time.Duration
	scanner     *bufio.Scanner
	translator  contracts.Translator
	model       string
	toolMap     map[string]string
	now         func() time.Time

	terminal  error
	closed    bool
	idleFired bool
	mu        sync.Mutex

	closeOnce sync.Once
	closeErr  error
}

var _ contracts.Stream = (*sseStream)(nil)

// Headers implements contracts.Stream.
func (s *sseStream) Headers() http.Header { return s.headers }

// Recv implements contracts.Stream: the next canonical chunk, io.EOF at a clean
// end, or a typed DomainError on failure.
func (s *sseStream) Recv() (contracts.Chunk, error) {
	if term := s.terminalOutcome(); term != nil {
		return contracts.Chunk{}, term
	}
	for {
		if err := s.ctx.Err(); err != nil {
			return contracts.Chunk{}, s.record(transportError(err))
		}
		line, ok, err := s.readFrame()
		if err != nil {
			return contracts.Chunk{}, s.record(err)
		}
		if !ok {
			return contracts.Chunk{}, s.record(io.EOF)
		}
		// A CloudCode frame wraps the Gemini payload in {"response": {...}};
		// unwrap before translating.
		canonical, err := s.translator.ResponseChunk(unwrapResponse(line), s.model)
		if err != nil {
			return contracts.Chunk{}, s.record(badFrame(err))
		}
		if len(canonical) == 0 {
			continue
		}
		canonical = s.uncloak(canonical)
		return contracts.Chunk{Data: canonical}, nil
	}
}

// readFrame reads one `data:` payload from the SSE stream, skipping comments and
// blank lines. ok=false means a clean EOF.
func (s *sseStream) readFrame() ([]byte, bool, error) {
	if s.idleTimeout > 0 {
		stop := s.armIdleWatch()
		defer stop()
	}
	for {
		if s.ctx.Err() != nil {
			return nil, false, transportError(s.ctx.Err())
		}
		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return nil, false, s.readError(err)
			}
			return nil, false, nil // clean EOF
		}
		line := s.scanner.Bytes()
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 {
			continue
		}
		// The `[DONE]` sentinel is the TERMINATOR, not a frame (D-01): return a
		// clean EOF (ok=false) so no consumer ever sees it as a chunk. Shared
		// with the OpenAI decoder via contracts.IsSSEDone so the two cannot
		// diverge.
		if contracts.IsSSEDone(payload) {
			return nil, false, nil
		}
		return payload, true, nil
	}
}

// uncloak reverts cloaked tool names in a canonical chunk.
func (s *sseStream) uncloak(canonical []byte) []byte {
	if len(s.toolMap) == 0 {
		return canonical
	}
	out, err := uncloakToolNames(canonical, s.toolMap)
	if err != nil {
		return canonical
	}
	return out
}

// terminalOutcome reads the terminal outcome under mu.
func (s *sseStream) terminalOutcome() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal
}

// record makes err terminal and returns the stored outcome.
func (s *sseStream) record(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal == nil {
		s.terminal = err
	}
	return s.terminal
}

// readError classifies a scanner error caused by our own close.
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

// armIdleWatch starts a watcher that closes the body after the idle budget and
// is JOINED by stop(), so it never outlives readFrame and never leaks.
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
			<-stopped
		})
	}
}

// closeBody closes the body exactly once, from any goroutine, without touching
// the Recv mutex.
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
func (s *sseStream) Close() error { return s.closeBody() }

// badFrame maps a frame-translation failure to a typed provider error, so a
// malformed upstream frame is never reported as a bare error.
func badFrame(err error) error {
	return domain.New(domain.CodeBadUpstreamResponse,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithScope(domain.ScopeProvider),
		domain.WithCause(err),
	)
}

// --- single-chunk stream (non-streaming model via DoStream) ---

// singleChunkStream yields one canonical chunk then io.EOF.
type singleChunkStream struct {
	headers http.Header
	body    []byte
	emitted bool
	closes  int
}

var _ contracts.Stream = (*singleChunkStream)(nil)

func newSingleChunkStream(status int, headers http.Header, body []byte) *singleChunkStream {
	return &singleChunkStream{headers: headers, body: body}
}

// Headers implements contracts.Stream.
func (s *singleChunkStream) Headers() http.Header { return s.headers }

// Recv implements contracts.Stream.
func (s *singleChunkStream) Recv() (contracts.Chunk, error) {
	if s.emitted {
		return contracts.Chunk{}, io.EOF
	}
	s.emitted = true
	return contracts.Chunk{Data: s.body}, nil
}

// Close implements contracts.Stream.
func (s *singleChunkStream) Close() error { s.closes++; return nil }
