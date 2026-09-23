package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// TestChainGatesAccessor covers the Gates accessor (0% before) and that the
// returned slice is a copy, not the internal one.
func TestChainGatesAccessor(t *testing.T) {
	g := preOnly("a", contracts.FailOpen, nil)
	chain, _ := New([]contracts.Gate{g})
	got := chain.Gates()
	if len(got) != 1 || got[0].ID() != "a" {
		t.Fatalf("Gates() = %v", got)
	}
	// Mutating the returned slice must not affect the chain.
	got[0] = nil
	if chain.Gates()[0] == nil {
		t.Error("Gates() returned the internal slice")
	}
}

// TestPreRequestUnknownDecisionIsAnError covers the default branch: a gate that
// returns an out-of-range DecisionKind fails closed.
func TestPreRequestUnknownDecisionIsAnError(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("bad", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionKind(99)}, nil
		}),
	})
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err == nil {
		t.Fatal("unknown decision kind accepted")
	}
}

// TestPreRequestRerouteWithoutTargetFailsClosed covers the missing-target branch.
func TestPreRequestRerouteWithoutTargetFailsClosed(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("r", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionReroute}, nil
		}),
	})
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err == nil {
		t.Fatal("reroute without a target accepted")
	}
}

// TestOnResponseChunkUnknownKindFailsClosed covers the chunk default branch.
func TestOnResponseChunkUnknownKindFailsClosed(t *testing.T) {
	gate := &recordingGate{
		id: "bad", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen,
		chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
			return contracts.ChunkDecision{Kind: contracts.ChunkDecisionKind(99)}, nil
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	if _, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{}); err == nil {
		t.Fatal("unknown chunk kind accepted")
	}
}

// TestOnResponseChunkFailPolicies covers both chunk error policies.
func TestOnResponseChunkFailPolicies(t *testing.T) {
	boom := errors.New("chunk boom")

	t.Run("fail closed", func(t *testing.T) {
		gate := &recordingGate{
			id: "c", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailClosed,
			chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
				return contracts.ChunkDecision{}, boom
			},
		}
		chain, _ := New([]contracts.Gate{gate})
		if _, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{}); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the gate error", err)
		}
	})

	t.Run("fail open", func(t *testing.T) {
		var afterRan bool
		chain, _ := New([]contracts.Gate{
			&recordingGate{
				id: "c1", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen,
				chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
					return contracts.ChunkDecision{}, boom
				},
			},
			&recordingGate{
				id: "c2", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen,
				chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
					afterRan = true
					return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
				},
			},
		})
		if _, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{}); err != nil {
			t.Fatalf("fail-open chunk aborted: %v", err)
		}
		if !afterRan {
			t.Error("a later gate did not run after a fail-open chunk error")
		}
	})
}

// TestPostResponseIsAlwaysFailOpen proves ADR-0014 §2: the post-response stage
// has NO policy choice — every gate runs and the first error is only reported
// (never short-circuits). Even a gate declaring FailClosed is treated as
// FailOpen here, because the exchange already happened.
func TestPostResponseIsAlwaysFailOpen(t *testing.T) {
	boom := errors.New("post boom")
	var secondRan bool
	chain, _ := New([]contracts.Gate{
		&recordingGate{
			id: "p1", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailClosed,
			post: func(context.Context, contracts.GateInput) error { return boom },
		},
		&recordingGate{
			id: "p2", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen,
			post: func(context.Context, contracts.GateInput) error { secondRan = true; return nil },
		},
	})
	if err := chain.PostResponse(context.Background(), contracts.GateInput{}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the first gate error reported", err)
	}
	if !secondRan {
		t.Error("a later post-response gate did not run; the stage is always FailOpen")
	}
}

// TestStagesAreSkippedWhenNotDeclared covers the "gate does not declare this
// stage -> continue" branch in each of the three stage loops: a gate registered
// for one stage must be skipped by the others.
func TestStagesAreSkippedWhenNotDeclared(t *testing.T) {
	// A post-only gate.
	postOnly := &recordingGate{
		id: "post", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen,
		post: func(context.Context, contracts.GateInput) error { return nil },
	}
	preOnlyGate := preOnly("pre", contracts.FailOpen, nil)
	chunkOnly := &recordingGate{
		id: "chunk", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen,
		chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
			return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
		},
	}

	chain, _ := New([]contracts.Gate{postOnly, preOnlyGate, chunkOnly})

	// PreRequest skips postOnly and chunkOnly.
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	// OnResponseChunk skips postOnly and preOnly.
	if _, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{}); err != nil {
		t.Fatalf("OnResponseChunk: %v", err)
	}
	// PostResponse skips preOnly and chunkOnly.
	if err := chain.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
}

// TestPreRequestModifyHeaders covers the header-rewrite branch of Modify.
func TestPreRequestModifyHeaders(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("h", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{
				Kind:    contracts.DecisionModify,
				Headers: map[string][]string{"X-New": {"v"}},
			}, nil
		}),
	})
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
}
