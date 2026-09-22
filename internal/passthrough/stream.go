package passthrough

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// streamBufferSize is the bounded channel depth between the upstream reader and
// the downstream writer. A bound is the backpressure mechanism: if the client
// reads slowly, the reader goroutine blocks on send instead of buffering the
// whole response in memory.
const streamBufferSize = 16

// StreamResult reports what happened during a streamed relay.
type StreamResult struct {
	// Committed is true once the first byte reached the downstream client. After
	// that a reroute or model switch is forbidden and errors must be delivered
	// as in-band SSE events, never as an HTTP status change.
	Committed bool
	// Bytes is the number of downstream bytes written.
	Bytes int64
}

// chunk is one unit flowing from the reader goroutine to the relay loop.
type chunk struct {
	data []byte
	err  error
}

// Stream relays an upstream call to w as Server-Sent Events. It returns a
// StreamResult and, when nothing has been committed yet, an error the caller
// may still surface as an HTTP status.
//
// Flow:
//  1. Send the upstream request.
//  2. A non-2xx upstream response is an error and nothing is committed.
//  3. On 2xx, mark committed and relay 200 + headers downstream.
//  4. Pump chunks through a bounded channel; a post-commit failure is encoded as
//     an SSE error event so the client sees a terminal event instead of a
//     truncated 200.
//  5. Cancellation is honoured via ctx.Done() on the send and receive sides.
func (c *Client) Stream(ctx context.Context, body []byte, w http.ResponseWriter) (StreamResult, error) {
	var result StreamResult

	upstreamReq, err := c.newRequest(ctx, body)
	if err != nil {
		return result, transportError(err)
	}
	upstreamReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(upstreamReq)
	if err != nil {
		return result, transportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, upstreamError(resp)
	}

	flusher, _ := w.(http.Flusher)

	// From here the response is committed: the status line is about to go out
	// and can no longer be changed.
	result.Committed = true
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	// pumpCtx so every return path below stops the reader goroutine, including
	// the write-error path where the caller's ctx is still alive.
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Reader goroutine. It owns the upstream body and stops as soon as the
	// context is cancelled, so a client disconnect does not leave it blocked on
	// a send.
	chunks := make(chan chunk, streamBufferSize)
	go func() {
		defer close(chunks)
		buf := make([]byte, 32<<10)
		for {
			if pumpCtx.Err() != nil {
				return
			}
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				// Copy: buf is reused on the next iteration and the main loop
				// must not observe a torn buffer.
				payload := make([]byte, n)
				copy(payload, buf[:n])
				select {
				case chunks <- chunk{data: payload}:
				case <-pumpCtx.Done():
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return
				}
				// Either hand the error to the main loop or give up because the
				// context was cancelled; both paths end this goroutine. The
				// explicit return in the Done arm keeps the branch a real,
				// testable block rather than an empty no-op arm.
				select {
				case chunks <- chunk{err: readErr}:
				case <-pumpCtx.Done():
					return
				}
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// Client hung up or deadline exceeded. Do not write an error event:
			// nobody is listening.
			return result, nil
		case ch, ok := <-chunks:
			if !ok {
				return result, nil
			}
			if ch.err != nil {
				// Committed: the only honest way to signal failure is an
				// in-band event.
				writeSSEError(w, flusher, domain.New(domain.CodeUpstreamUnavailable,
					domain.WithHTTPStatus(http.StatusBadGateway),
					domain.WithCause(ch.err),
				))
				return result, nil
			}
			n, writeErr := w.Write(ch.data)
			result.Bytes += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
			if writeErr != nil {
				// The downstream is gone; stop.
				return result, nil
			}
		}
	}
}

// writeSSEError emits a terminal SSE error event.
func writeSSEError(w http.ResponseWriter, flusher http.Flusher, de *domain.DomainError) {
	payload := `{"error":{"code":"` + de.Code + `"}}`
	_, _ = w.Write([]byte("event: error\ndata: " + payload + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}
