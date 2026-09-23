package security

import (
	"context"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// TestCredentialMaskerStripsBearerAndAPIKey is the required assertion: the
// masker removes Bearer tokens and sk- keys from the body through the central
// redactor, and a clean body is left byte-identical (Continue, not Modify).
func TestCredentialMaskerStripsBearerAndAPIKey(t *testing.T) {
	g := NewCredentialMasker()
	body := []byte(`{"messages":[{"role":"user","content":"my key is Authorization: Bearer abc123defXYZ and sk-abcdefgh12"}]}`)

	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: map[string]string{}})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if dec.Kind != contracts.DecisionModify {
		t.Fatalf("kind = %v, want Modify", dec.Kind)
	}
	out := string(dec.Body)
	if strings.Contains(out, "abc123defXYZ") || strings.Contains(out, "sk-abcdefgh12") {
		t.Fatalf("secret survived masking: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("masking placeholder missing: %s", out)
	}

	clean := []byte(`{"messages":[{"role":"user","content":"plain text, no secrets"}]}`)
	dec, err = g.PreRequest(context.Background(), contracts.GateInput{Body: clean})
	if err != nil {
		t.Fatalf("PreRequest clean: %v", err)
	}
	if dec.Kind != contracts.DecisionContinue {
		t.Fatalf("clean body kind = %v, want Continue", dec.Kind)
	}
	if string(dec.Body) != "" {
		t.Fatalf("clean body must not be rewritten, got %s", dec.Body)
	}
}

// TestCredentialMaskerFailClosedOnInvalidBody pins the FailClosed behaviour at
// gate level: a body the masker cannot process yields an error (the chain
// aborts; it never forwards unaudited content).
func TestCredentialMaskerFailClosedOnInvalidBody(t *testing.T) {
	g := NewCredentialMasker()
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{broken`)})
	if err == nil {
		t.Fatal("invalid body: want error (FailClosed)")
	}
	if dec.Kind != contracts.DecisionContinue {
		t.Fatalf("decision on error must be zero, got %v", dec.Kind)
	}
}

// TestCredentialMaskerEmptyBodyAndNoMeta covers the nil-body continue and the
// nil-Meta tolerance (direct callers may not supply scratch space).
func TestCredentialMaskerEmptyBodyAndNoMeta(t *testing.T) {
	g := NewCredentialMasker()
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("empty body: dec=%v err=%v", dec, err)
	}
	// Secret with nil Meta: must not panic, still modifies.
	dec, err = g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{"c":"token abcdef123456"}`)})
	if err != nil || dec.Kind != contracts.DecisionModify {
		t.Fatalf("nil meta: dec=%v err=%v", dec, err)
	}
}

// TestCredentialMaskerMetadataAndContract pins identity, stages, caps, policy,
// body declaration and graph declaration (containment, phase 1).
func TestCredentialMaskerMetadataAndContract(t *testing.T) {
	g := NewCredentialMasker()
	if g.ID() != IDCredentialMasker {
		t.Fatalf("id = %s", g.ID())
	}
	if !g.Stages().Has(contracts.StagePreRequest) || g.Stages().Has(contracts.StageOnResponseChunk) || g.Stages().Has(contracts.StagePostResponse) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailClosed {
		t.Fatalf("policy = %v, want FailClosed", g.FailurePolicy())
	}
	if !g.NeedsBody() {
		t.Fatal("masker must declare NeedsBody")
	}
	d := g.Declare()
	if len(d.Writes) != 1 || d.Writes[0] != contracts.FieldPromptText {
		t.Fatalf("declared writes = %v, want [prompt_text]", d.Writes)
	}
	if len(d.Reads) != 0 {
		t.Fatalf("declared reads = %v, want none", d.Reads)
	}

	chunk, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{Body: []byte("secret")})
	if err != nil || chunk.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk: %v %v", chunk, err)
	}
	if err := g.PostResponse(context.Background(), contracts.GateInput{Body: []byte("secret")}); err != nil {
		t.Fatalf("post response: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestCredentialMaskerMetaCount records the redaction count under the gate's
// namespace and never the content.
func TestCredentialMaskerMetaCount(t *testing.T) {
	g := NewCredentialMasker()
	meta := map[string]string{}
	body := []byte(`{"a":"password hunter2secret","b":"x"}`)
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: meta})
	if err != nil || dec.Kind != contracts.DecisionModify {
		t.Fatalf("dec=%v err=%v", dec, err)
	}
	if meta[IDCredentialMasker+".redactions"] != "1" {
		t.Fatalf("meta = %v", meta)
	}
	for k, v := range meta {
		if strings.Contains(v, "hunter2secret") {
			t.Fatalf("meta[%s] leaks content: %s", k, v)
		}
	}
}
