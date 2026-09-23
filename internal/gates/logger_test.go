package gates

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func sampleInput(secret string) contracts.GateInput {
	return contracts.GateInput{
		RequestID:  domain.RequestID("req-1"),
		Provider:   domain.ProviderID("z.ai"),
		Credential: domain.CredentialID("cred-1"),
		Model:      domain.ModelID("glm-5"),
		Headers: http.Header{
			"Content-Type":  {"application/json"},
			"Authorization": {"Bearer " + secret},
		},
		Body: []byte(`{"prompt":"` + secret + `"}`),
	}
}

// TestLoggerGateNeverLogsBodyOrHeaderValues is the P1-E invariant: the gate
// emits metadata only, so neither a body nor an auth header value can reach the
// sink.
func TestLoggerGateNeverLogsBodyOrHeaderValues(t *testing.T) {
	const secret = "sk-live-SUPER-SECRET-TOKEN-123456"

	var records []string
	g := NewLogger(func(stage string, fields map[string]string) {
		var sb strings.Builder
		sb.WriteString(stage)
		for k, v := range fields {
			sb.WriteString("|")
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
		}
		records = append(records, sb.String())
	})

	in := sampleInput(secret)
	if _, err := g.PreRequest(context.Background(), in); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	chunk := contracts.ChunkInput{
		RequestID: in.RequestID,
		Provider:  in.Provider,
		Body:      []byte("data: " + secret),
		Index:     0,
	}
	if _, err := g.OnResponseChunk(context.Background(), chunk); err != nil {
		t.Fatalf("OnResponseChunk: %v", err)
	}
	if err := g.PostResponse(context.Background(), in); err != nil {
		t.Fatalf("PostResponse: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("records = %d, want 3 (one per stage)", len(records))
	}
	for _, rec := range records {
		if strings.Contains(rec, secret) {
			t.Fatalf("logger gate leaked a secret: %s", rec)
		}
	}
	// The header NAME must be present (useful), the VALUE absent (safe).
	if !strings.Contains(records[0], "header_names=") || !strings.Contains(records[0], "Authorization") {
		t.Errorf("expected header names in the record: %s", records[0])
	}
}

func TestLoggerGateMetadata(t *testing.T) {
	var last map[string]string
	g := NewLogger(func(stage string, fields map[string]string) { last = fields })

	if _, err := g.PreRequest(context.Background(), sampleInput("x-long-enough")); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	for _, key := range []string{"request_id", "provider", "credential", "model"} {
		if last[key] == "" {
			t.Errorf("metadata missing %q: %+v", key, last)
		}
	}
}

func TestLoggerGateContractShape(t *testing.T) {
	g := NewLogger(nil)
	if g.ID() != "logger" {
		t.Errorf("ID = %q", g.ID())
	}
	stages := g.Stages()
	for _, st := range []contracts.GateStage{
		contracts.StagePreRequest, contracts.StageOnResponseChunk, contracts.StagePostResponse,
	} {
		if !stages.Has(st) {
			t.Errorf("stage %v not declared", st)
		}
	}
	if g.RequiredCaps() != 0 {
		t.Errorf("RequiredCaps = %v, want 0", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailOpen {
		t.Errorf("FailurePolicy = %v, want FailOpen", g.FailurePolicy())
	}
	if err := g.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestLoggerDerivedBranches covers metadataOf's three shapes: a Derived WITH a
// preallocated Fields map (reused directly), a Derived WITHOUT one (identity
// fields filled in, no header join), and no Derived (fall back to the input).
func TestLoggerDerivedBranches(t *testing.T) {
	var last map[string]string
	g := NewLogger(func(_ string, fields map[string]string) { last = fields })

	// (a) Derived with Fields: reused verbatim.
	withFields := &contracts.Derived{Fields: map[string]string{"request_id": "r", "custom": "x"}}
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Derived: withFields}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if last["custom"] != "x" {
		t.Fatalf("Derived.Fields not reused: %+v", last)
	}

	// (b) Derived without Fields: identity copied, header name from Derived.
	noFields := &contracts.Derived{RequestID: "r2", Provider: "p", Credential: "c", Model: "m", HeaderNames: "A,B"}
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Derived: noFields}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if last["request_id"] != "r2" || last["header_names"] != "A,B" {
		t.Fatalf("Derived-without-Fields = %+v", last)
	}
	// A Derived with no header names omits the key entirely.
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Derived: &contracts.Derived{RequestID: "r3"}}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if _, ok := last["header_names"]; ok {
		t.Fatalf("empty header names leaked a key: %+v", last)
	}

	// (c) No Derived: fall back to the input headers.
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{
		RequestID: "r4", Headers: http.Header{"Authorization": {"secret"}},
	}); err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if last["header_names"] != "Authorization" {
		t.Fatalf("fallback header names = %+v", last)
	}
}

func TestLoggerGateAlwaysContinues(t *testing.T) {
	g := NewLogger(nil)
	d, err := g.PreRequest(context.Background(), sampleInput("token-value"))
	if err != nil || d.Kind != contracts.DecisionContinue {
		t.Fatalf("decision = %+v, %v", d, err)
	}
	cd, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{Body: []byte("x")})
	if err != nil || cd.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk decision = %+v, %v", cd, err)
	}
}
