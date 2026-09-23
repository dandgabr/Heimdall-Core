package contracts

import (
	"context"
	"testing"
)

// bodyGate is a minimal Gate that optionally declares a body need.
type bodyGate struct {
	id     string
	needs  bool
	stages GateStageSet
	policy FailurePolicy
}

func (g bodyGate) ID() string                   { return g.id }
func (g bodyGate) Stages() GateStageSet         { return g.stages }
func (g bodyGate) RequiredCaps() GateCaps       { return 0 }
func (g bodyGate) FailurePolicy() FailurePolicy { return g.policy }
func (g bodyGate) PreRequest(_ context.Context, _ GateInput) (Decision, error) {
	return Decision{Kind: DecisionContinue}, nil
}
func (g bodyGate) OnResponseChunk(_ context.Context, _ ChunkInput) (ChunkDecision, error) {
	return ChunkDecision{Kind: ChunkPassThrough}, nil
}
func (g bodyGate) PostResponse(_ context.Context, _ GateInput) error { return nil }
func (g bodyGate) Close() error                                      { return nil }
func (g bodyGate) NeedsBody() bool                                   { return g.needs }

// plainGate is a Gate that does NOT implement BodyConsumer.
type plainGate struct{ bodyGate }

func (p plainGate) ID() string { return p.bodyGate.id }

// TestConsumesBody covers nil, a non-BodyConsumer, a BodyConsumer that needs the
// body, and one that does not.
func TestConsumesBody(t *testing.T) {
	if ConsumesBody(nil) {
		t.Fatal("nil gate consumes the body")
	}
	if ConsumesBody(plainGate{bodyGate{id: "p"}}) {
		t.Fatal("a non-BodyConsumer consumes the body")
	}
	if !ConsumesBody(bodyGate{id: "b", needs: true}) {
		t.Fatal("a needing BodyConsumer was not detected")
	}
	if ConsumesBody(bodyGate{id: "b", needs: false}) {
		t.Fatal("a non-needing BodyConsumer was detected as needing")
	}
}

// TestAnyConsumesBody covers the empty slice, all-plain, and a needing gate.
func TestAnyConsumesBody(t *testing.T) {
	if AnyConsumesBody(nil) {
		t.Fatal("empty slice reported a body need")
	}
	if AnyConsumesBody([]Gate{nil, plainGate{bodyGate{id: "p"}}}) {
		t.Fatal("no consumer reported a body need")
	}
	if !AnyConsumesBody([]Gate{plainGate{bodyGate{id: "p"}}, bodyGate{id: "b", needs: true}}) {
		t.Fatal("a needing consumer was missed")
	}
}
