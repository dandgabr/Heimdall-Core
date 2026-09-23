package pipeline

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// bodyGate declares it needs the body, to exercise ConsumesRequestBody.
type bodyGate struct{ recordingGate }

func (bodyGate) NeedsBody() bool { return true }

// TestPreRequestReturnsAccumulatedModify is the F4-wave-2 regression: a Modify
// gate's body must reach the CALLER (not only the downstream working input), or
// every Modify gate is a no-op for the request that goes upstream.
func TestPreRequestReturnsAccumulatedModify(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("mod", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionModify, Body: []byte("CHANGED")}, nil
		}),
	})
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{Body: []byte("orig")})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Kind != contracts.DecisionModify {
		t.Fatalf("kind = %v, want Modify (the caller must receive the change)", d.Kind)
	}
	if string(d.Body) != "CHANGED" {
		t.Fatalf("body = %q, want CHANGED", d.Body)
	}
}

// TestPreRequestModifyThenNoopReturnsModify proves the accumulated Modify is
// still returned when a later gate leaves the body unchanged.
func TestPreRequestModifyThenNoopReturnsModify(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("mod", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionModify, Body: []byte("CHANGED")}, nil
		}),
		preOnly("noop", contracts.FailOpen, nil),
	})
	d, _ := chain.PreRequest(context.Background(), contracts.GateInput{Body: []byte("orig")})
	if d.Kind != contracts.DecisionModify || string(d.Body) != "CHANGED" {
		t.Fatalf("decision = %v / %q", d.Kind, d.Body)
	}
}

// TestPreRequestModifyHeadersOnlyReturnsModify proves a header-only Modify is
// also surfaced.
func TestPreRequestModifyHeadersOnlyReturnsModify(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("mod", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionModify, Headers: map[string][]string{"X-New": {"v"}}}, nil
		}),
	})
	d, _ := chain.PreRequest(context.Background(), contracts.GateInput{})
	if d.Kind != contracts.DecisionModify || d.Headers.Get("X-New") != "v" {
		t.Fatalf("decision = %v / %v", d.Kind, d.Headers)
	}
}

// TestChainConsumesRequestBody proves the chain reports the body need from its
// PRE-REQUEST gates only (a chunk-only body consumer does not trigger delivery
// at the pre-request boundary).
func TestChainConsumesRequestBody(t *testing.T) {
	// No consumer.
	plain, _ := New([]contracts.Gate{
		&recordingGate{id: "p", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen},
	})
	if plain.ConsumesRequestBody() {
		t.Fatal("plain chain reported a body need")
	}

	// A pre-request body consumer.
	bg := bodyGate{recordingGate{id: "b", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen}}
	withBody, _ := New([]contracts.Gate{&bg})
	if !withBody.ConsumesRequestBody() {
		t.Fatal("chain did not report the body need")
	}

	// A chunk-only consumer must NOT trigger pre-request body delivery.
	chunkBg := bodyGate{recordingGate{id: "c", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen}}
	chunkOnly, _ := New([]contracts.Gate{&chunkBg})
	if chunkOnly.ConsumesRequestBody() {
		t.Fatal("a chunk-only consumer triggered pre-request body delivery")
	}

	// Empty chain.
	empty, _ := New(nil)
	if empty.ConsumesRequestBody() {
		t.Fatal("empty chain reported a body need")
	}
}

// TestConsumesBodyHelpers covers the nil/non-consumer cases of the contract
// helpers.
func TestConsumesBodyHelpers(t *testing.T) {
	if contracts.ConsumesBody(nil) {
		t.Fatal("nil gate consumes the body")
	}
	plain := &recordingGate{id: "p", stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen}
	if contracts.ConsumesBody(plain) {
		t.Fatal("a non-BodyConsumer reported a body need")
	}
	if contracts.AnyConsumesBody([]contracts.Gate{nil, plain}) {
		t.Fatal("AnyConsumesBody reported a need without a consumer")
	}
}

// TestNewOrderedRejectsNilGate covers both NewOrdered nil-guards.
func TestNewOrderedRejectsNilGate(t *testing.T) {
	if _, err := NewOrdered([]contracts.Gate{nil}, nil, nil); err == nil {
		t.Fatal("nil pre gate accepted")
	}
	if _, err := NewOrdered(nil, nil, []contracts.Gate{nil}); err == nil {
		t.Fatal("nil post gate accepted")
	}
}

// TestNewOrderedDedupesAll proves a gate present in several stages appears once
// in All, ID-sorted, and Gates() is a copy.
func TestNewOrderedDedupesAll(t *testing.T) {
	g := &recordingGate{id: "multi", stages: contracts.StageSet(
		contracts.StagePreRequest, contracts.StageOnResponseChunk, contracts.StagePostResponse), policy: contracts.FailOpen}
	chain, err := NewOrdered([]contracts.Gate{g}, []contracts.Gate{g}, []contracts.Gate{g})
	if err != nil {
		t.Fatalf("NewOrdered: %v", err)
	}
	if got := chain.Gates(); len(got) != 1 || got[0].ID() != "multi" {
		t.Fatalf("Gates() = %v, want the one distinct gate", got)
	}
	got := chain.Gates()
	got[0] = nil
	if chain.Gates()[0] == nil {
		t.Fatal("Gates() returned the internal slice")
	}
}

// TestNewOrderedRunsInGivenOrder proves the chain runs gates in the order the
// registry computed, per stage (not re-sorted).
func TestNewOrderedRunsInGivenOrder(t *testing.T) {
	var order []string
	mk := func(id string) *recordingGate {
		return &recordingGate{id: id, stages: contracts.StageSet(contracts.StagePreRequest), policy: contracts.FailOpen,
			pre: func(context.Context, contracts.GateInput) (contracts.Decision, error) {
				order = append(order, id)
				return contracts.Decision{Kind: contracts.DecisionContinue}, nil
			}}
	}
	// Deliberately NOT alphabetical: the chain must not re-sort.
	chain, err := NewOrdered([]contracts.Gate{mk("zeta"), mk("alpha")}, nil, nil)
	if err != nil {
		t.Fatalf("NewOrdered: %v", err)
	}
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if len(order) != 2 || order[0] != "zeta" || order[1] != "alpha" {
		t.Fatalf("order = %v, want the given order [zeta alpha]", order)
	}
}

// TestPreRequestComputesDerivedOnce proves the chain computes the request-scoped
// Derived once and returns it on the decision, and that an already-supplied
// Derived is reused (pointer identity).
func TestPreRequestComputesDerivedOnce(t *testing.T) {
	chain, _ := New(nil)
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{
		RequestID: "r1", Provider: "p", Credential: "c", Model: "m",
		Headers: map[string][]string{"B": {""}, "A": {""}},
	})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Derived == nil {
		t.Fatal("PreRequest did not compute Derived")
	}
	if d.Derived.HeaderNames != "A,B" {
		t.Fatalf("header names = %q, want A,B (sorted)", d.Derived.HeaderNames)
	}
	if d.Derived.Fields["request_id"] != "r1" || d.Derived.Fields["header_names"] != "A,B" {
		t.Fatalf("fields = %+v", d.Derived.Fields)
	}

	// An already-supplied Derived is reused, not recomputed.
	supplied := &contracts.Derived{RequestID: "keep"}
	d2, _ := chain.PreRequest(context.Background(), contracts.GateInput{Derived: supplied})
	if d2.Derived != supplied {
		t.Fatal("PreRequest recomputed an already-supplied Derived")
	}
}

// TestDeriveNeverReadsHeaderValues proves SEC-13 at the Derive boundary: only
// names are joined, never values.
func TestDeriveNeverReadsHeaderValues(t *testing.T) {
	d := Derive(contracts.GateInput{Headers: map[string][]string{
		"Authorization": {"Bearer SUPER-SECRET"}, "Cookie": {"session=SUPER-SECRET"},
	}})
	if d.HeaderNames != "Authorization,Cookie" {
		t.Fatalf("names = %q", d.HeaderNames)
	}
	for _, v := range d.Fields {
		if v == "Bearer SUPER-SECRET" || v == "session=SUPER-SECRET" {
			t.Fatalf("Derive leaked a header value: %+v", d.Fields)
		}
	}
}

// TestOnResponseChunkStampsScalarsOnce proves the chain stamps the per-chunk
// scalars into the shared Derived map once, visible to every gate.
func TestOnResponseChunkStampsScalarsOnce(t *testing.T) {
	var seen map[string]string
	gate := &recordingGate{
		id: "obs", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen,
		chunk: func(_ context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error) {
			seen = in.Derived.Fields
			return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
		},
	}
	chain, _ := New([]contracts.Gate{gate})
	d := &contracts.Derived{Fields: map[string]string{}}
	if _, err := chain.OnResponseChunk(context.Background(), contracts.ChunkInput{Body: []byte("hello"), Index: 3, Derived: d}); err != nil {
		t.Fatalf("OnResponseChunk: %v", err)
	}
	if seen["chunk_index"] != "3" || seen["chunk_bytes"] != "5" {
		t.Fatalf("scalars = %v", seen)
	}
	// The scalars are cleared before PostResponse.
	_ = chain.PostResponse(context.Background(), contracts.GateInput{Derived: d})
	if _, ok := d.Fields["chunk_index"]; ok {
		t.Fatal("chunk_index survived into PostResponse")
	}
}

// TestClearChunkScalarsNil guards the nil/nil-Fields branches.
func TestClearChunkScalarsNil(t *testing.T) {
	clearChunkScalars(nil)                                             // nil Derived
	clearChunkScalars(&contracts.Derived{})                            // nil Fields
	clearChunkScalars(&contracts.Derived{Fields: map[string]string{}}) // empty, no panic
}

// TestStampChunkScalarsNil guards the nil/nil-Fields branches of stamping.
func TestStampChunkScalarsNil(t *testing.T) {
	stampChunkScalars(nil, 1, 2)
	stampChunkScalars(&contracts.Derived{}, 1, 2)
}

// TestPostResponseComputesDerivedWhenAbsent covers the nil-Derived branch.
func TestPostResponseComputesDerivedWhenAbsent(t *testing.T) {
	var sawNil bool
	gate := &recordingGate{id: "p", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen,
		post: func(_ context.Context, in contracts.GateInput) error {
			sawNil = in.Derived != nil
			return nil
		}}
	chain, _ := New([]contracts.Gate{gate})
	if err := chain.PostResponse(context.Background(), contracts.GateInput{RequestID: "r"}); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}
	if !sawNil {
		t.Fatal("PostResponse did not compute Derived")
	}
}

// TestPreRequestFailOpenDoesNotPublishPartialModify proves ADR-0014 §3.3: a
// FailOpen gate that errors mid-Modify leaves the input UNMODIFIED for the next
// gate.
func TestPreRequestFailOpenDoesNotPublishPartialModify(t *testing.T) {
	var sawBody string
	chain, _ := New([]contracts.Gate{
		preOnly("flaky", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{}, errBoom
		}),
		preOnly("after", contracts.FailOpen, func(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
			sawBody = string(in.Body)
			return contracts.Decision{Kind: contracts.DecisionContinue}, nil
		}),
	})
	if _, err := chain.PreRequest(context.Background(), contracts.GateInput{Body: []byte("original")}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if sawBody != "original" {
		t.Fatalf("body = %q, want the original (no partial modify)", sawBody)
	}
}

// TestPreRequestBlockCarriesDerived proves a terminal Block/Reroute decision
// carries the Derived for the caller.
func TestPreRequestBlockCarriesDerived(t *testing.T) {
	chain, _ := New([]contracts.Gate{
		preOnly("block", contracts.FailOpen, func(context.Context, contracts.GateInput) (contracts.Decision, error) {
			return contracts.Decision{Kind: contracts.DecisionBlock, Synthetic: &contracts.SyntheticResponse{Status: 200}}, nil
		}),
	})
	d, err := chain.PreRequest(context.Background(), contracts.GateInput{RequestID: "r"})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if d.Derived == nil || d.Derived.RequestID != "r" {
		t.Fatalf("block decision Derived = %+v", d.Derived)
	}
}

// TestStageNameMapping covers the stage-name helper used by the boot log.
func TestChainPartitionLegacyNew(t *testing.T) {
	// New partitions a flat list by stage, preserving order.
	pre := preOnly("p", contracts.FailOpen, nil)
	chunk := &recordingGate{id: "c", stages: contracts.StageSet(contracts.StageOnResponseChunk), policy: contracts.FailOpen}
	post := &recordingGate{id: "o", stages: contracts.StageSet(contracts.StagePostResponse), policy: contracts.FailOpen}
	chain, err := New([]contracts.Gate{pre, chunk, post})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(chain.pre) != 1 || len(chain.chunk) != 1 || len(chain.post) != 1 {
		t.Fatalf("partition = %d/%d/%d", len(chain.pre), len(chain.chunk), len(chain.post))
	}
	if chain.pre[0].ID() != "p" || chain.chunk[0].ID() != "c" || chain.post[0].ID() != "o" {
		t.Fatal("partition order wrong")
	}
	_ = domain.CodeInternal
}
