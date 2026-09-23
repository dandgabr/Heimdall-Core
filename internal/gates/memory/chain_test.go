package memory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/gates"
	"github.com/dandgabr/heimdall-core/internal/gates/token"
	"github.com/dandgabr/heimdall-core/internal/pipeline"
)

// TestDerivedOrderMemoryBeforeToken pins the SEC-04 phase edge: the retriever
// WRITES context and the token engine READS it, so the graph orders
// memory-retriever → token (context assembly before compression). The writer
// is post-response only.
func TestDerivedOrderMemoryBeforeToken(t *testing.T) {
	r := gates.NewRegistry()
	if err := r.RegisterGate(IDMemoryRetriever, func() contracts.Gate { return NewRetriever(Config{Store: &fakeStore{}}) }); err != nil {
		t.Fatalf("register retriever: %v", err)
	}
	if err := r.RegisterGate(IDMemoryWriter, func() contracts.Gate { return NewWriter(Config{Store: &fakeStore{}}) }); err != nil {
		t.Fatalf("register writer: %v", err)
	}
	tok := token.New(token.Config{})
	if err := r.RegisterGate(tok.ID(), func() contracts.Gate { return tok }); err != nil {
		t.Fatalf("register token: %v", err)
	}
	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	pre := idsOfGates(order.PreRequest)
	if len(pre) != 2 || pre[0] != IDMemoryRetriever || pre[1] != "token" {
		t.Fatalf("pre order = %v, want [memory-retriever token]", pre)
	}
	post := idsOfGates(order.PostResponse)
	if len(post) != 1 || post[0] != IDMemoryWriter {
		t.Fatalf("post order = %v, want [memory-writer]", post)
	}
}

// TestChainFailOpenNeverDropsTheRequest runs the retriever through the REAL
// chain: a store failure is swallowed by the FailOpen policy and the request
// proceeds unmodified.
func TestChainFailOpenNeverDropsTheRequest(t *testing.T) {
	r := gates.NewRegistry()
	if err := r.RegisterGate(IDMemoryRetriever, func() contracts.Gate {
		return NewRetriever(Config{Store: &fakeStore{searchErr: errors.New("db down")}})
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	chain, err := pipeline.NewOrdered(order.PreRequest, order.OnResponseChunk, order.PostResponse)
	if err != nil {
		t.Fatalf("NewOrdered: %v", err)
	}
	body := chatBody("any question")
	dec, err := chain.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: map[string]string{MetaKeyClient: "k"}})
	if err != nil {
		t.Fatalf("fail-open violated: %v", err)
	}
	if dec.Kind != contracts.DecisionContinue {
		t.Fatalf("kind = %v, want Continue", dec.Kind)
	}
}

// TestChainRetrieverInjectsThroughPipeline runs retriever + token engine in
// the real chain: the injected memory survives compression (it is outside the
// original messages array, but the collapse-whitespace engine keeps strings)
// and the final decision carries the modified body.
func TestChainRetrieverInjectsThroughPipeline(t *testing.T) {
	r := gates.NewRegistry()
	if err := r.RegisterGate(IDMemoryRetriever, func() contracts.Gate {
		return NewRetriever(Config{
			Store: &fakeStore{searchHits: []contracts.MemoryHit{
				{Content: "the deploy window is tuesday", Provenance: contracts.SourceUser, TurnID: "req-1"},
			}},
		})
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	tok := token.New(token.Config{Engines: []token.CompressionEngine{token.NewCollapseWhitespace()}})
	if err := r.RegisterGate(tok.ID(), func() contracts.Gate { return tok }); err != nil {
		t.Fatalf("register token: %v", err)
	}
	order, err := r.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	chain, err := pipeline.NewOrdered(order.PreRequest, nil, nil)
	if err != nil {
		t.Fatalf("NewOrdered: %v", err)
	}
	dec, err := chain.PreRequest(context.Background(), contracts.GateInput{
		Body: chatBody("when is the deploy window?"),
		Meta: map[string]string{MetaKeyClient: "client-a"},
	})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if dec.Kind != contracts.DecisionModify {
		t.Fatalf("kind = %v, want Modify", dec.Kind)
	}
	out := string(dec.Body)
	if !strings.Contains(out, "<retrieved_memory") || !strings.Contains(out, "deploy window") {
		t.Fatalf("injected memory lost through the chain: %s", out)
	}
}

func idsOfGates(gs []contracts.Gate) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID())
	}
	return out
}
