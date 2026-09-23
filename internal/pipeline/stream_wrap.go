package pipeline

import (
	"context"
	"io"
	"net/http"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// syntheticStream is a one-chunk Stream carrying a gate's SyntheticResponse. It
// is the pre-commit Block path: the pipeline emits the synthetic as a normal
// successful stream (a semantic-cache hit is a success, not an error), then EOF.
type syntheticStream struct {
	headers  http.Header
	body     []byte
	onClose  func()
	emitted  bool
	closeOne sync.Once
}

var _ contracts.Stream = (*syntheticStream)(nil)

// Headers implements contracts.Stream.
func (s *syntheticStream) Headers() http.Header { return s.headers }

// Recv implements contracts.Stream: one chunk, then io.EOF.
func (s *syntheticStream) Recv() (contracts.Chunk, error) {
	if s.emitted {
		return contracts.Chunk{}, io.EOF
	}
	s.emitted = true
	return contracts.Chunk{Event: "message", Data: s.body}, nil
}

// Close implements contracts.Stream: idempotent, runs the post-response hook once.
func (s *syntheticStream) Close() error {
	s.closeOne.Do(func() {
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

// closingStream wraps an inner Stream so:
//
//   - every chunk returned by Recv is passed through the chain's
//     OnResponseChunk stage, so a post-commit gate can Replace or Drop it
//     (the F4 security/memory gates would otherwise be no-ops on the stream);
//   - PostResponse runs exactly once when the caller closes it, whether the
//     stream ended cleanly or errored.
type closingStream struct {
	contracts.Stream
	chain    *Chain
	ctx      context.Context
	base     contracts.GateInput
	onClose  func()
	index    int
	closeOne sync.Once
}

var _ contracts.Stream = (*closingStream)(nil)

// Recv implements contracts.Stream. It pulls the next chunk from the inner
// stream and applies the chain's per-chunk decision: PassThrough returns the
// chunk unchanged, Replace swaps its Data, and Drop discards it and pulls again
// (the stream itself continues). A FailClosed gate error is returned verbatim;
// a FailOpen one is already swallowed by the chain.
func (s *closingStream) Recv() (contracts.Chunk, error) {
	for {
		ch, err := s.Stream.Recv()
		if err != nil {
			return contracts.Chunk{}, err
		}
		if s.chain == nil {
			// No chain: pure pass-through (the decorator is always built with a
			// chain, but a hand-built wrapper must not panic).
			return ch, nil
		}
		in := contracts.ChunkInput{
			RequestID:  s.base.RequestID,
			Provider:   s.base.Provider,
			Credential: s.base.Credential,
			Model:      s.base.Model,
			Headers:    s.base.Headers,
			Body:       ch.Data,
			Index:      s.index,
			Committed:  true,
			Meta:       s.base.Meta,
			// The request-scoped Derived computed in PreRequest is reused here
			// (ADR-0014 §6): the chunk path does not rebuild metadata.
			Derived: s.base.Derived,
		}
		s.index++

		decision, err := s.chain.OnResponseChunk(s.ctx, in)
		if err != nil {
			return contracts.Chunk{}, err
		}
		switch decision.Kind {
		case contracts.ChunkReplace:
			ch.Data = decision.Body
			return ch, nil
		case contracts.ChunkDrop:
			continue
		default: // ChunkPassThrough
			return ch, nil
		}
	}
}

// Close implements contracts.Stream: closes the inner stream then runs the hook
// once.
func (s *closingStream) Close() error {
	var err error
	s.closeOne.Do(func() {
		err = s.Stream.Close()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return err
}
