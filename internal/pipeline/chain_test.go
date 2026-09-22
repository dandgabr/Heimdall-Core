package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/gates"
)

// recordingGate is a configurable test gate.
type recordingGate struct {
	id       string
	stages   contracts.GateStageSet
	policy   contracts.FailurePolicy
	pre      func(context.Context, contracts.GateInput) (contracts.Decision, error)
	chunk    func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error)
	post     func(context.Context, contracts.GateInput) error
	closeErr error
}

func (g *recordingGate) ID() string                             { return g.id }
func (g *recordingGate) Stages() contracts.GateStageSet         { return g.stages }
func (g *recordingGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (g *recordingGate) FailurePolicy() contracts.FailurePolicy { return g.policy }
func (g *recordingGate) PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if g.pre != nil {
		return g.pre(ctx, in)
	}
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (g *recordingGate) OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
	if g.chunk != nil {
		return g.chunk(ctx, in)
	}
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (g *recordingGate) PostResponse(ctx context.Context, in contracts.GateInput) error {
	if g.post != nil {
		return g.post(ctx, in)
	}
	return nil
}
func (g *recordingGate) Close() error { return g.closeErr }

func preOnly(id string, policy contracts.FailurePolicy, fn func(context.Context, contracts.GateInput) (contracts.Decision, error)) *recordingGate {
	return &recordingGate{id: id, stages: contracts.StageSet(contracts.StagePreRequest), policy: policy, pre: fn}
}

func TestChainRejectsNilGate(t *testing.T) {
	if _, err := New([]contracts.Gate{nil}); err == nil {
		t.Fatal("nil gate accepted")
	}
}

// TestChainOrderIsDeterministic: gates run in the slice order, and a Modify from
// an early gate is visible to a later one.
func TestChainOrderIsDeterministic(t *testing.T) {
	var order []string
	chain, err := New([]contracts.Gate{
		preOnly("a", contracts.FailOpen, func(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
			order = append(order, "a")
			return contracts.Decision{Kind: contracts.DecisionModify, Body: []byte("modified-by-a")}, nil
		}),
		preOnly("b", contracts.FailOpen, func(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
			order = append(order, "b")
			if string(in.Body) != "modified-by-a" {
				t.Errorf("gate b saw body %q, want the modification from a", in.Body)
			}
			return contracts.Decision{Kind: contracts.DecisionContinue}, nil
		}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if fmt.Sprint(order) != "[a b]" {
		t.Fatalf("order = %v", order)
	}
}

func TestChainBlockIsTerminalAndCarriesSynthetic(t *testing.T) {
	var afterRan bool
	chain, _ := New([]contracts.Gate{
		preOnly("blocker", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{
				Kind: contracts.DecisionBlock,
				Synthetic: &contracts.SyntheticResponse{
					Status:   http.StatusOK,
					Body:     []byte("cached"),
					CacheHit: true,
				},
			}, nil
		}),
		preOnly("after", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			afterRan = true
			return contracts.Decision{Kind: contracts.DecisionContinue}, nil
		}),
	})

	d, err := chain.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionBlock || d.Synthetic == nil || !d.Synthetic.CacheHit {
		t.Fatalf("decision = %+v", d)
	}
	if afterRan {
		t.Error("a gate ran after a Block; Block must be terminal")
	}
}

func TestChainBlockWithoutSyntheticFailsClosed(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("bad", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionBlock}, nil
		}),
	})
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err == nil {
		t.Fatal("Block without a SyntheticResponse was accepted")
	}
}

func TestChainReroute(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("rerouter", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{
				Kind:    contracts.DecisionReroute,
				Reroute: &contracts.RerouteTarget{Provider: "other", Model: "m"},
			}, nil
		}),
	})
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionReroute || d.Reroute == nil || d.Reroute.Provider != "other" {
		t.Fatalf("decision = %+v", d)
	}
}

// TestChainFailurePolicies pins the per-gate policy: FailClosed aborts,
// FailOpen continues.
func TestChainFailurePolicies(t *testing.T) {
	boom := errors.New("gate exploded")

	t.Run("fail closed aborts", func(t *testing.T) {
		var afterRan bool
		chain, _ := New([]contracts.Gate{
			preOnly("closed", contracts.FailClosed, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
				return contracts.Decision{}, boom
			}),
			preOnly("after", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
				afterRan = true
				return contracts.Decision{Kind: contracts.DecisionContinue}, nil
			}),
		})
		_, err := chain.PreRequest(context.Background(), contracts.GateInput{})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the gate error", err)
		}
		if afterRan {
			t.Error("a gate ran after a FailClosed error")
		}
	})

	t.Run("fail open continues", func(t *testing.T) {
		var afterRan bool
		chain, _ := New([]contracts.Gate{
			preOnly("open", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
				return contracts.Decision{}, boom
			}),
			preOnly("after", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
				afterRan = true
				return contracts.Decision{Kind: contracts.DecisionContinue}, nil
			}),
		})
		if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err != nil {
			t.Fatalf("FailOpen aborted: %v", err)
		}
		if !afterRan {
			t.Error("pipeline did not continue after a FailOpen error")
		}
	})
}

// TestChainChunkForcesCommitted proves the chain sets Committed=true for the
// chunk stage, so a gate cannot mistake a post-commit call for pre-commit.
func TestChainChunkForcesCommitted(t *testing.T) {
	var sawCommitted bool
	gate := &recordingGate{
		id:     "chunk",
		stages: contracts.StageSet(contracts.StageOnResponseChunk),
		policy: contracts.FailOpen,
		chunk: func(_ context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
			sawCommitted = in.Committed
			return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
		},
	}
	chain, _ := New([]contracts.Gate{gate})

	// Pass Committed=false; the chain must override it.
	_, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{Committed: false})
	if err != nil {
		t.Fatalf("OnResponseChunk: %v", err)
	}
	if !sawCommitted {
		t.Error("chunk stage did not force Committed=true")
	}
}

func TestChainChunkDecisionKinds(t *testing.T) {
	tests := []struct {
		name string
		kind contracts.ChunkDecisionKind
		want contracts.ChunkDecisionKind
	}{
		{"passthrough", contracts.ChunkPassThrough, contracts.ChunkPassThrough},
		{"replace", contracts.ChunkReplace, contracts.ChunkReplace},
		{"drop", contracts.ChunkDrop, contracts.ChunkDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := &recordingGate{
				id:     "c",
				stages: contracts.StageSet(contracts.StageOnResponseChunk),
				policy: contracts.FailOpen,
				chunk: func(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
					return contracts.ChunkDecision{Kind: tt.kind, Body: []byte("b")}, nil
				},
			}
			chain, _ := New([]contracts.Gate{gate})
			d, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{})
			if err != nil {
				t.Fatalf("OnResponseChunk: %v", err)
			}
			if d.Kind != tt.want {
				t.Errorf("kind = %v, want %v", d.Kind, tt.want)
			}
		})
	}
}

func TestChainPostResponsePolicies(t *testing.T) {
	boom := errors.New("post failed")

	t.Run("fail closed returns error", func(t *testing.T) {
		gate := &recordingGate{
			id:     "p",
			stages: contracts.StageSet(contracts.StagePostResponse),
			policy: contracts.FailClosed,
			post:   func(context.Context, contracts.GateInput) error { return boom },
		}
		chain, _ := New([]contracts.Gate{gate})
		if err := chain.PostResponse(context.Background(), contracts.GateInput{}); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the gate error", err)
		}
	})

	t.Run("fail open still runs the others", func(t *testing.T) {
		var secondRan bool
		chain, _ := New([]contracts.Gate{
			&recordingGate{id: "p1", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen,
				post: func(context.Context, contracts.GateInput) error { return boom }},
			&recordingGate{id: "p2", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen,
				post: func(context.Context, contracts.GateInput) error { secondRan = true; return nil }},
		})
		if err := chain.PostResponse(context.Background(), contracts.GateInput{}); err == nil {
			t.Error("expected the FailOpen error to be reported")
		}
		if !secondRan {
			t.Error("a FailOpen post-response error stopped the chain")
		}
	})
}

func TestChainCloseJoinsErrors(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		&recordingGate{id: "a", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen,
			closeErr: errors.New("close a")},
		&recordingGate{id: "b", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen,
			closeErr: errors.New("close b")},
	})
	err := chain.Close()
	if err == nil {
		t.Fatal("expected joined errors")
	}
	if !errors.Is(err, errors.New("close a")) {
		// errors.Is with a fresh error never matches; assert via string instead.
		if !containsAll(err.Error(), "close a", "close b") {
			t.Fatalf("Close error = %v, want both gate errors", err)
		}
	}
}

// TestChainWithRealLoggerGate exercises the F1 wiring: the trivial logger gate
// participates in all stages and never blocks.
func TestChainWithRealLoggerGate(t *testing.T) {
	chain, err := New([]contracts.Gate{gates.NewLogger(nil)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{RequestID: "r"})
	if err != nil || d.Kind != contracts.DecisionContinue {
		t.Fatalf("decision = %+v, %v", d, err)
	}
	c, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{Body: []byte("x")})
	if err != nil || c.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk = %+v, %v", c, err)
	}
	if err := chain.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
