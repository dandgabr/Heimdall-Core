package dispatcher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// outcome is one winning attempt: the candidate, the wire response (non-stream)
// or the live stream, and the attempts consumed to reach it.
type outcome struct {
	candidate contracts.Candidate
	wire      contracts.WireResponse
	stream    contracts.Stream
	attempts  int
}

// wrappingStream accounts a streamed attempt. It forwards Recv verbatim and, at
// the terminal outcome, records the usage observed across the stream: a clean
// end reports the accumulated tokens as `ok`, an abort (client disconnect, idle
// timeout, mid-stream error) reports the tokens seen so far as `aborted`
// (ADR-0011 §5). Close triggers the same accounting exactly once.
//
// It never mutates the stream's bytes: accounting is a side channel.
type wrappingStream struct {
	inner  contracts.Stream
	disp   *Dispatcher
	cc     contracts.Candidate
	key    string
	done   sync.Once
	tokens int
	input  int
	output int
}

var _ contracts.Stream = (*wrappingStream)(nil)

// Headers implements contracts.Stream.
func (s *wrappingStream) Headers() http.Header { return s.inner.Headers() }

// Recv implements contracts.Stream. It accumulates the token counts it can read
// from each chunk (best-effort; a non-JSON chunk contributes nothing) and, on a
// terminal outcome, finalises the accounting.
func (s *wrappingStream) Recv() (contracts.Chunk, error) {
	ch, err := s.inner.Recv()
	if err != nil {
		// io.EOF is a clean end; any other error is an abort that still spent
		// quota. Both finalise the attempt once.
		s.finalise(err == io.EOF)
		return ch, err
	}
	s.absorb(ch.Data)
	return ch, nil
}

// Close implements contracts.Stream: it closes the inner stream and finalises
// the accounting once (a stream closed without Recv reaching EOF is an abort).
func (s *wrappingStream) Close() error {
	err := s.inner.Close()
	s.finalise(false)
	return err
}

// absorb reads a canonical chunk's usage, when present, and accumulates it. A
// chunk without a usage block contributes nothing.
func (s *wrappingStream) absorb(data []byte) {
	if len(data) == 0 || !strings.Contains(string(data), "usage") {
		return
	}
	var payload struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}
	in, out := payload.Usage.PromptTokens, payload.Usage.CompletionTokens
	if in == 0 {
		in = payload.Usage.InputTokens
	}
	if out == 0 {
		out = payload.Usage.OutputTokens
	}
	if payload.Usage.TotalTokens > 0 {
		s.tokens = payload.Usage.TotalTokens
	} else if in+out > 0 {
		s.tokens = in + out
	}
	s.input, s.output = in, out
}

// finalise records the streamed usage exactly once. A wrapper is only built
// when a recorder exists (wrapStream returns the raw stream otherwise), so the
// recorder here is never nil; the guard is defensive.
func (s *wrappingStream) finalise(clean bool) {
	s.done.Do(func() {
		u := contracts.Usage{
			AttemptKey:   s.key,
			Provider:     s.cc.Provider,
			Credential:   s.cc.Credential,
			Model:        s.cc.Model,
			Tokens:       s.tokens,
			InputTokens:  s.input,
			OutputTokens: s.output,
			Requests:     1,
			Aborted:      !clean,
		}
		outcome := contracts.OutcomeSuccess
		if !clean {
			outcome = contracts.OutcomeTransient
		}
		_ = s.disp.recorder.Record(context.Background(), outcome, u)
	})
}

// wrapStream wraps a winning stream for accounting.
func (d *Dispatcher) wrapStream(inner contracts.Stream, c contracts.Candidate, key string) contracts.Stream {
	if d.recorder == nil {
		return inner
	}
	return &wrappingStream{inner: inner, disp: d, cc: c, key: key}
}
