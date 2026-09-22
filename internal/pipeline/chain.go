// Package pipeline holds the GateChain: the ordered execution of gates with the
// pre-commit / post-commit distinction that the frozen contracts.Gate defines.
//
// The chain is deliberately small and owns no I/O. Its job is to run the
// registered gates for one stage, apply their failure policy, and stop the
// pipeline when a gate blocks. Committed is threaded through so a post-commit
// gate can only emit a ChunkDecision (no reroute, no model swap).
package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Chain runs gates in a deterministic order.
//
// Order is the registration order supplied by the caller (the GateRegistry
// sorts names before building), so the chain itself never iterates a map.
type Chain struct {
	gates []contracts.Gate
}

// New builds a chain. A nil gate is rejected: a half-built chain would silently
// drop a security control.
func New(gates []contracts.Gate) (*Chain, error) {
	for i, g := range gates {
		if g == nil {
			return nil, domain.New(domain.CodeInternal,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": fmt.Sprintf("gate %d is nil", i)}),
			)
		}
	}
	return &Chain{gates: append([]contracts.Gate(nil), gates...)}, nil
}

// Gates returns the gates in order. It returns a COPY: a caller that mutated the
// slice would otherwise be able to null out a gate and silently disable a
// security control.
func (c *Chain) Gates() []contracts.Gate {
	out := make([]contracts.Gate, len(c.gates))
	copy(out, c.gates)
	return out
}

// PreRequest runs every gate that declares StagePreRequest, in order.
//
// It stops at the first Block or Reroute (both are terminal for the loop) and
// returns the accumulated decision. A Modify updates the working input and
// continues. On a gate error the contract's FailurePolicy decides: FailClosed
// aborts with the gate's error, FailOpen logs (via the error return's presence)
// and continues.
//
// Committed is forced false here: PreRequest is by definition pre-commit.
func (c *Chain) PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error) {
	in.Committed = false

	for _, g := range c.gates {
		if !g.Stages().Has(contracts.StagePreRequest) {
			continue
		}
		decision, err := g.PreRequest(ctx, in)
		if err != nil {
			if g.FailurePolicy() == contracts.FailClosed {
				return contracts.Decision{}, err
			}
			continue // FailOpen: ignore and continue
		}

		switch decision.Kind {
		case contracts.DecisionContinue:
			continue
		case contracts.DecisionModify:
			// A Modify rewrites the request for the REMAINING gates.
			if decision.Body != nil {
				in.Body = decision.Body
			}
			if decision.Headers != nil {
				in.Headers = decision.Headers
			}
			continue
		case contracts.DecisionBlock:
			if decision.Synthetic == nil {
				return contracts.Decision{}, domain.New(domain.CodeInternal,
					domain.WithHTTPStatus(500),
					domain.WithParams(map[string]string{"reason": "gate " + g.ID() + " blocked without a synthetic response"}),
				)
			}
			return decision, nil
		case contracts.DecisionReroute:
			if decision.Reroute == nil {
				return contracts.Decision{}, domain.New(domain.CodeInternal,
					domain.WithHTTPStatus(500),
					domain.WithParams(map[string]string{"reason": "gate " + g.ID() + " rerouted without a target"}),
				)
			}
			return decision, nil
		default:
			return contracts.Decision{}, domain.New(domain.CodeInternal,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "gate " + g.ID() + " returned an unknown decision"}),
			)
		}
	}
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}

// OnResponseChunk runs every gate that declares StageOnResponseChunk, in order.
//
// Committed is forced true: the first byte has already been sent, so the only
// legal outcomes are PassThrough, Replace and Drop. A gate that returns an
// unknown kind is a contract violation and fails closed.
func (c *Chain) OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	in.Committed = true

	for _, g := range c.gates {
		if !g.Stages().Has(contracts.StageOnResponseChunk) {
			continue
		}
		decision, err := g.OnResponseChunk(ctx, in)
		if err != nil {
			if g.FailurePolicy() == contracts.FailClosed {
				return contracts.ChunkDecision{}, err
			}
			continue
		}
		switch decision.Kind {
		case contracts.ChunkPassThrough:
			continue
		case contracts.ChunkReplace:
			return decision, nil
		case contracts.ChunkDrop:
			return decision, nil
		default:
			return contracts.ChunkDecision{}, domain.New(domain.CodeInternal,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "gate " + g.ID() + " returned an unknown chunk decision"}),
			)
		}
	}
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse runs every gate that declares StagePostResponse, in order. It
// returns the first FailClosed error; FailOpen errors are collected but do not
// abort the others (the exchange already happened and should not be lost).
func (c *Chain) PostResponse(ctx context.Context, in contracts.GateInput) error {
	var firstErr error
	for _, g := range c.gates {
		if !g.Stages().Has(contracts.StagePostResponse) {
			continue
		}
		if err := g.PostResponse(ctx, in); err != nil {
			if g.FailurePolicy() == contracts.FailClosed {
				if firstErr == nil {
					firstErr = err
				}
				return firstErr
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Close releases every gate. It attempts all of them and returns the joined
// errors, so one misbehaving Close does not strand the others.
func (c *Chain) Close() error {
	var errs []error
	for _, g := range c.gates {
		if err := g.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
