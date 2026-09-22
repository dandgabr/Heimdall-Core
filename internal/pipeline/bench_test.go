package pipeline

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/gates"
)

// This file is measurement-only: it benchmarks the GateChain stages with 1 and
// with 10 gates. The per-chunk stage is the hottest path of the F2 streaming
// pipeline. No production code is touched.
//
//	go test ./internal/pipeline -bench . -benchmem -count=5

func benchHeaders() http.Header {
	return http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"heimdall/0.1"},
		"Accept":       {"text/event-stream"},
		"X-Request-Id": {"0193f0c1-aaaa-bbbb-cccc-ddddeeeeffff"},
	}
}

func benchGateInput() contracts.GateInput {
	return contracts.GateInput{
		RequestID:  domain.RequestID("0193f0c1-aaaa-bbbb-cccc-ddddeeeeffff"),
		Provider:   domain.ProviderID("openai-compat"),
		Credential: domain.CredentialID("cred-1"),
		Model:      domain.ModelID("gpt-4o-mini"),
		Headers:    benchHeaders(),
		Meta:       map[string]string{"http.method": "POST", "http.path": "/v1/chat/completions"},
	}
}

func benchChunkInput() contracts.ChunkInput {
	return contracts.ChunkInput{
		RequestID:  domain.RequestID("0193f0c1-aaaa-bbbb-cccc-ddddeeeeffff"),
		Provider:   domain.ProviderID("openai-compat"),
		Credential: domain.CredentialID("cred-1"),
		Model:      domain.ModelID("gpt-4o-mini"),
		Headers:    benchHeaders(),
		Body:       make([]byte, 256),
		Index:      7,
	}
}

// benchChainLogger builds a chain of n real logger gates (the only production
// gate in F1), with a no-op sink so the benchmark measures the gate's own work.
func benchChainLogger(b *testing.B, n int) *Chain {
	b.Helper()
	gs := make([]contracts.Gate, n)
	for i := range gs {
		gs[i] = gates.NewLogger(nil)
	}
	c, err := New(gs)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return c
}

// benchChainNoop builds a chain of n pass-through gates, to separate the chain's
// own loop overhead from the gate implementation cost.
func benchChainNoop(b *testing.B, n int) *Chain {
	b.Helper()
	gs := make([]contracts.Gate, n)
	for i := range gs {
		gs[i] = &recordingGate{
			id:     "noop",
			stages: contracts.StageSet(contracts.StagePreRequest, contracts.StageOnResponseChunk, contracts.StagePostResponse),
			policy: contracts.FailOpen,
		}
	}
	c, err := New(gs)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return c
}

var gateCounts = []int{1, 10}

func BenchmarkChainPreRequest(b *testing.B) {
	ctx := context.Background()
	for _, kind := range []struct {
		name  string
		build func(*testing.B, int) *Chain
	}{
		{"noop", benchChainNoop},
		{"logger", benchChainLogger},
	} {
		for _, n := range gateCounts {
			b.Run(kind.name+"/gates="+strconv.Itoa(n), func(b *testing.B) {
				chain := kind.build(b, n)
				in := benchGateInput()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := chain.PreRequest(ctx, in); err != nil {
						b.Fatalf("PreRequest: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkChainOnResponseChunk(b *testing.B) {
	ctx := context.Background()
	for _, kind := range []struct {
		name  string
		build func(*testing.B, int) *Chain
	}{
		{"noop", benchChainNoop},
		{"logger", benchChainLogger},
	} {
		for _, n := range gateCounts {
			b.Run(kind.name+"/gates="+strconv.Itoa(n), func(b *testing.B) {
				chain := kind.build(b, n)
				in := benchChunkInput()
				b.SetBytes(int64(len(in.Body)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := chain.OnResponseChunk(ctx, in); err != nil {
						b.Fatalf("OnResponseChunk: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkChainPostResponse(b *testing.B) {
	ctx := context.Background()
	for _, kind := range []struct {
		name  string
		build func(*testing.B, int) *Chain
	}{
		{"noop", benchChainNoop},
		{"logger", benchChainLogger},
	} {
		for _, n := range gateCounts {
			b.Run(kind.name+"/gates="+strconv.Itoa(n), func(b *testing.B) {
				chain := kind.build(b, n)
				in := benchGateInput()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := chain.PostResponse(ctx, in); err != nil {
						b.Fatalf("PostResponse: %v", err)
					}
				}
			})
		}
	}
}
