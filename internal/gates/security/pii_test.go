package security

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestPIIMaskerMasksAllTypes is the required assertion: e-mail, phone, CPF and
// a Luhn-valid card are all masked with typed placeholders.
func TestPIIMaskerMasksAllTypes(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiMask})
	if g == nil {
		t.Fatal("mask policy must construct the gate")
	}
	body := []byte(`{"content":"mail me at joana@example.com or (11) 91234-5678; cpf 123.456.789-09; card 4111 1111 1111 1111"}`)

	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: map[string]string{}})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if dec.Kind != contracts.DecisionModify {
		t.Fatalf("kind = %v, want Modify", dec.Kind)
	}
	out := string(dec.Body)
	for _, leak := range []string{"joana@example.com", "91234-5678", "123.456.789-09", "4111 1111 1111 1111"} {
		if strings.Contains(out, leak) {
			t.Fatalf("PII survived masking: %s", leak)
		}
	}
	for _, want := range []string{phEmail, phPhone, phCPF, phCard} {
		if !strings.Contains(out, want) {
			t.Fatalf("placeholder %s missing in %s", want, out)
		}
	}
	if !strings.Contains(out, `"content":"`) {
		t.Fatalf("JSON structure broken: %s", out)
	}
}

// TestPIIMaskerLuhnFiltersNonCards proves the checksum filter: a digit run
// that looks like a card but fails Luhn is NOT masked, a valid one is, and a
// short run is below the card floor. The body also carries a clean item so the
// decision is a Modify.
func TestPIIMaskerLuhnFiltersNonCards(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiMask})
	body := []byte(`{"a":"valid 4111 1111 1111 1111 bad 4111 1111 1111 1122 short 1234 5678 9012 end"}`)
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if dec.Kind != contracts.DecisionModify {
		t.Fatalf("kind = %v, want Modify (the valid card is masked)", dec.Kind)
	}
	out := string(dec.Body)
	// The Luhn-valid card is masked.
	if strings.Contains(out, "valid 4111") {
		t.Fatalf("valid card must be masked: %s", out)
	}
	if !strings.Contains(out, phCard) {
		t.Fatalf("card placeholder missing: %s", out)
	}
	// 4111 1111 1111 1122 fails Luhn → untouched.
	if !strings.Contains(out, "bad 4111 1111 1111 1122") {
		t.Fatalf("Luhn-invalid run must not be masked: %s", out)
	}
	// 1234 5678 9012 is 12 digits: below the 13-digit floor, untouched.
	if !strings.Contains(out, "short 1234 5678 9012 end") {
		t.Fatalf("short digit run must not be masked: %s", out)
	}
}

// TestPIIMaskerBlockPolicy is the block branch: the refusal lists TYPES only,
// never the payload, and carries a 400 synthetic with the standard envelope.
func TestPIIMaskerBlockPolicy(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiBlock})
	body := []byte(`{"content":"email maria@example.com and cpf 987.654.321-00"}`)
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: map[string]string{}})
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}
	if dec.Kind != contracts.DecisionBlock {
		t.Fatalf("kind = %v, want Block", dec.Kind)
	}
	if dec.Synthetic == nil || dec.Synthetic.Status != 400 {
		t.Fatalf("synthetic = %+v, want 400", dec.Synthetic)
	}
	if dec.Code != domain.CodeSecurityPIIBlocked {
		t.Fatalf("code = %s", dec.Code)
	}
	if dec.Params["types"] != "email,cpf" {
		t.Fatalf("types = %q, want email,cpf", dec.Params["types"])
	}
	var env envelope
	if err := json.Unmarshal(dec.Synthetic.Body, &env); err != nil {
		t.Fatalf("synthetic body is not the error envelope: %s", dec.Synthetic.Body)
	}
	if env.Error.Code != domain.CodeSecurityPIIBlocked || env.Error.Params["types"] != "email,cpf" {
		t.Fatalf("envelope = %s", dec.Synthetic.Body)
	}
	// The raw PII must appear on no output surface.
	raw := string(dec.Synthetic.Body) + dec.Code + dec.Params["types"]
	if strings.Contains(raw, "maria@example.com") || strings.Contains(raw, "987.654.321-00") {
		t.Fatal("block decision carries payload content")
	}
	if got := dec.Synthetic.Headers.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
}

// TestPIIMaskerCleanAndEmpty covers the continue paths.
func TestPIIMaskerCleanAndEmpty(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiBlock})
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: nil})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("empty: %v %v", dec, err)
	}
	dec, err = g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(`{"content":"no personal data here"}`)})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("clean: %v %v", dec, err)
	}
}

// TestPIIMaskerFailClosedOnInvalidBody pins the FailClosed error path.
func TestPIIMaskerFailClosedOnInvalidBody(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiMask})
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte("not json")}); err == nil {
		t.Fatal("invalid body: want error")
	}
}

// TestNewPIIMaskerOffIsNil pins "off ⇒ not constructed".
func TestNewPIIMaskerOffIsNil(t *testing.T) {
	if NewPIIMasker(PiiConfig{Policy: PiiOff}) != nil {
		t.Fatal("off policy must not construct a gate")
	}
	// The zero policy is Mask (safe default), never off.
	if NewPIIMasker(PiiConfig{}) == nil {
		t.Fatal("zero policy must construct the gate")
	}
}

// TestPIIMaskerMetadataAndContract pins identity/declaration/contract surface.
func TestPIIMaskerMetadataAndContract(t *testing.T) {
	g := NewPIIMasker(PiiConfig{Policy: PiiBlock})
	if g.ID() != IDPIIMasker {
		t.Fatalf("id = %s", g.ID())
	}
	if g.Stages() != contracts.StageSet(contracts.StagePreRequest) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailClosed {
		t.Fatal("PII masker must be FailClosed (registry refuses the opposite)")
	}
	if !g.NeedsBody() {
		t.Fatal("PII masker must declare NeedsBody")
	}
	d := g.Declare()
	if len(d.Reads) != 1 || d.Reads[0] != contracts.FieldPromptText {
		t.Fatalf("reads = %v, want [prompt_text]", d.Reads)
	}
	if len(d.Writes) != 1 || d.Writes[0] != contracts.FieldPII {
		t.Fatalf("writes = %v, want [pii]", d.Writes)
	}
	chunk, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{})
	if err != nil || chunk.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk: %v %v", chunk, err)
	}
	if err := g.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("post: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestPIIMaskerMetaTypes records the detected types (labels only) on both
// policies and never leaks values.
func TestPIIMaskerMetaTypes(t *testing.T) {
	for _, policy := range []PiiPolicy{PiiMask, PiiBlock} {
		g := NewPIIMasker(PiiConfig{Policy: policy})
		meta := map[string]string{}
		body := []byte(`{"c":"email a@b.com and phone (11) 91234-5678"}`)
		dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: meta})
		if err != nil {
			t.Fatalf("policy %d: %v", policy, err)
		}
		if policy == PiiMask && dec.Kind != contracts.DecisionModify {
			t.Fatalf("mask: kind = %v", dec.Kind)
		}
		if meta[IDPIIMasker+".types"] != "email,phone" {
			t.Fatalf("policy %d: meta = %v", policy, meta)
		}
	}
}

// TestPIIHelpers unit-tests the pure helpers on their branch edges.
func TestPIIHelpers(t *testing.T) {
	if !luhnValid("4111111111111111") {
		t.Fatal("valid card must pass Luhn")
	}
	if luhnValid("4111111111111122") {
		t.Fatal("invalid card must fail Luhn")
	}
	if luhnValid("0") || luhnValid("") {
		t.Fatal("too-short input must fail")
	}
	// A doubled digit above 9 wraps (18-9), exercising the d>9 branch: "91"
	// sums 1+9=10 → valid; "55" sums 5+1=6 → invalid.
	if !luhnValid("91") {
		t.Fatal("91 must pass Luhn (doubled 9 wraps to 9)")
	}
	if luhnValid("55") {
		t.Fatal("55 must fail Luhn")
	}
	if got := digitsOf("4111 1111-1111"); got != "411111111111" {
		t.Fatalf("digitsOf = %s", got)
	}
	if placeholderFor("email") != phEmail || placeholderFor("card") != phCard ||
		placeholderFor("cpf") != phCPF || placeholderFor("anything") != phPhone {
		t.Fatal("placeholderFor mapping wrong")
	}
	if got := joinKinds([]string{"a", "b", "c"}); got != "a,b,c" {
		t.Fatalf("joinKinds = %s", got)
	}
	if got := joinKinds(nil); got != "" {
		t.Fatalf("joinKinds(nil) = %s", got)
	}
}
