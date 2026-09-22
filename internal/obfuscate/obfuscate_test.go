package obfuscate

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file holds behavioural tests: each one asserts a property that a golden
// file cannot (identity, purity, totality, error paths). They are deliberately
// not tautological — they check the OUTCOME, not that a function was called.

// --- Apply ---

// TestApplyIsIdentityWithoutObfuscation is the ADR-0003 §1 invariant: a
// descriptor with no obfuscation makes Apply return the body unchanged.
func TestApplyIsIdentityWithoutObfuscation(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"system","content":"opencode"}]}`)
	got, err := Apply(contracts.ProviderDescriptor{ID: "plain"}, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("Apply changed an unobfuscated body\n in: %s\nout: %s", body, got)
	}
}

// TestApplyIdentityReturnsDefensiveCopy proves the identity path does not alias
// caller memory.
func TestApplyIdentityReturnsDefensiveCopy(t *testing.T) {
	body := []byte(`{"model":"m"}`)
	got, err := Apply(contracts.ProviderDescriptor{}, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body[0] = 'X'
	if got[0] == 'X' {
		t.Fatal("Apply output aliases caller input")
	}
}

// TestApplyReturnsNilForNilInput covers copyBytes' nil branch.
func TestApplyReturnsNilForNilInput(t *testing.T) {
	got, err := Apply(contracts.ProviderDescriptor{}, nil)
	if err != nil || got != nil {
		t.Fatalf("Apply(nil) = %v, %v", got, err)
	}
}

// TestApplyLiteralReplacesEveryOccurrence pins that a literal rewrite is global.
func TestApplyLiteralReplacesEveryOccurrence(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "opencode", To: "antigravity"}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":"opencode opencode opencode"}]}`)
	got, err := Apply(desc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if bytes.Contains(got, []byte("opencode")) {
		t.Fatalf("literal rewrite was not global: %s", got)
	}
	if n := bytes.Count(got, []byte("antigravity")); n != 3 {
		t.Fatalf("replaced %d occurrences, want 3: %s", n, got)
	}
}

// TestApplyRegexCaptureExpansion pins $1 capture expansion.
func TestApplyRegexCaptureExpansion(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{
				{From: `Hermes Agent, (an intelligent AI assistant)`, To: "Hermes Agent. $1", IsRegex: true},
			},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":"You are Hermes Agent, an intelligent AI assistant."}]}`)
	got, err := Apply(desc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Contains(got, []byte("Hermes Agent. an intelligent AI assistant")) {
		t.Fatalf("capture expansion failed: %s", got)
	}
}

// TestApplyInvalidRegexIsAnError is the "fail loudly" guarantee: a bad pattern in
// the descriptor is reported, never silently skipped.
func TestApplyInvalidRegexIsAnError(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "([", To: "x", IsRegex: true}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":"anything"}]}`)
	if _, err := Apply(desc, body); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

// TestApplyErrorPaths covers the malformed-body and malformed-messages branches.
func TestApplyErrorPaths(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "a", To: "b"}},
		},
	}
	if _, err := Apply(desc, []byte("{not json")); err == nil {
		t.Error("malformed body accepted")
	}
	if _, err := Apply(desc, []byte(`{"messages":"not-an-array"}`)); err == nil {
		t.Error("malformed messages accepted")
	}
	// A numeric content is not a string or an array, so the rewrite skips it
	// (unknown shape) rather than erroring: the function never guesses, and it
	// never loses data it did not touch.
	if _, err := Apply(desc, []byte(`{"messages":[{"role":"system","content":5}]}`)); err != nil {
		t.Errorf("numeric system content should pass through: %v", err)
	}
	if _, err := Apply(desc, []byte(`{"messages":[{"role":"system","content":{"unexpected":true}}]}`)); err != nil {
		t.Errorf("unknown content shape should pass through: %v", err)
	}
	if _, err := Apply(desc, []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":5}]}]}`)); err != nil {
		t.Errorf("non-string parts text should be skipped: %v", err)
	}
}

// TestApplySkipsEmptyFromAndNonSystem covers the empty-rule guard and the
// non-system message skip.
func TestApplySkipsEmptyFromAndNonSystem(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "", To: "x"}},
		},
	}
	body := []byte(`{"messages":[{"role":"user","content":"opencode"},{"role":"system","content":"opencode"}]}`)
	got, err := Apply(desc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if bytes.Contains(got, []byte("x")) {
		t.Fatalf("empty From produced a change: %s", got)
	}
}

// TestApplyNoChangeLeavesBodyShape verifies a rule that matches nothing leaves
// the system text intact (changed=false path).
func TestApplyNoChangeLeavesSystemIntact(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "absent", To: "x"}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":"untouched"},{"role":"user","content":"hi"}]}`)
	got, err := Apply(desc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Contains(got, []byte("untouched")) {
		t.Fatalf("system text changed without a match: %s", got)
	}
}

// TestApplyNullSystemContent covers the null-content early return.
func TestApplyNullSystemContent(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "a", To: "b"}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":null}]}`)
	if _, err := Apply(desc, body); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// --- CloakTools ---

// TestCloakToolsIsIdentityWithoutCloaking is the ADR-0003 §1 invariant for tools.
func TestCloakToolsIsIdentityWithoutCloaking(t *testing.T) {
	body := []byte(`{"tools":[{"type":"function","function":{"name":"t"}}]}`)
	got, unmap, err := CloakTools(contracts.ProviderDescriptor{ID: "plain"}, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("CloakTools changed an unobfuscated body\n in: %s\nout: %s", body, got)
	}
	if unmap != nil {
		t.Fatalf("unmap = %v, want nil", unmap)
	}
}

// TestCloakToolsNilInputIdentity covers the nil-body copyBytes branch.
func TestCloakToolsNilInput(t *testing.T) {
	got, unmap, err := CloakTools(contracts.ProviderDescriptor{}, nil)
	if err != nil || got != nil || unmap != nil {
		t.Fatalf("CloakTools(nil) = %v, %v, %v", got, unmap, err)
	}
}

// TestCloakToolsRoundTrip proves the map is exactly the reverse: cloaking and
// uncloaking the names yields the originals, including parallel calls.
func TestCloakToolsRoundTrip(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{
				NameSuffix: "_ide",
				DecoyTools: []contracts.ToolDecoy{{Name: "run_command", Description: "n/a"}},
			},
		},
	}
	body := []byte(`{"messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"a","parameters":{}}},{"type":"function","function":{"name":"b","parameters":{}}}]}`)
	_, unmap, err := CloakTools(desc, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	// Two client tools cloaked; the decoy is NOT in the map (it is not a rename).
	if len(unmap) != 2 {
		t.Fatalf("unmap size = %d, want 2: %v", len(unmap), unmap)
	}
	if got := UncloakToolName(unmap, "a_ide"); got != "a" {
		t.Errorf("a_ide -> %q, want a", got)
	}
	if got := UncloakToolName(unmap, "b_ide"); got != "b" {
		t.Errorf("b_ide -> %q, want b", got)
	}
	// A decoy passes through unchanged.
	if got := UncloakToolName(unmap, "run_command"); got != "run_command" {
		t.Errorf("decoy -> %q, want run_command", got)
	}
}

// TestUncloakIsTotal covers the nil map and unknown name branches.
func TestUncloakIsTotal(t *testing.T) {
	if got := UncloakToolName(nil, "x"); got != "x" {
		t.Errorf("nil map -> %q", got)
	}
	if got := UncloakToolName(map[string]string{"a": "b"}, "z"); got != "z" {
		t.Errorf("unknown -> %q", got)
	}
}

// TestCloakToolsErrorPaths covers the malformed-body and malformed-tools branches.
func TestCloakToolsErrorPaths(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{NameSuffix: "_x"},
		},
	}
	if _, _, err := CloakTools(desc, []byte("{bad")); err == nil {
		t.Error("malformed body accepted")
	}
	if _, _, err := CloakTools(desc, []byte(`{"tools":"nope"}`)); err == nil {
		t.Error("malformed tools accepted")
	}
	if _, _, err := CloakTools(desc, []byte(`{"messages":"nope"}`)); err == nil {
		t.Error("malformed messages accepted")
	}
}

// TestCloakToolsPassesNonFunctionTools exercises the openAIFunction miss path and
// the decoy-dedup path.
func TestCloakToolsPassesNonFunctionTools(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{
				NameSuffix: "_x",
				// The decoy name collides with the SUFFIXED client tool name
				// ("client" + "_x" == "client_x"), so it must be deduplicated.
				DecoyTools: []contracts.ToolDecoy{{Name: "client_x", Description: "d"}},
			},
		},
	}
	// First tool has no "function" (passes through); second, when suffixed,
	// collides with the decoy name "client_x", so the decoy is deduplicated.
	body := []byte(`{"tools":[{"type":"retrieval"},{"type":"function","function":{"name":"client"}}]}`)
	got, unmap, err := CloakTools(desc, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	var parsed struct {
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	names := make([]string, 0, len(parsed.Tools))
	for _, tl := range parsed.Tools {
		names = append(names, tl.Function.Name)
	}
	// retrieval (untouched, no function), client_x (renamed). The decoy
	// "client_x" is deduplicated, so it appears once.
	count := 0
	for _, n := range names {
		if n == "client_x" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("client_x appears %d times, want 1; names=%v", count, names)
	}
	if unmap["client_x"] != "client" {
		t.Fatalf("unmap = %v", unmap)
	}
}

// TestCloakToolsHistoryMalformedCallPassesThrough covers the history branches
// where a call has no function or a non-string name.
func TestCloakToolsHistoryMalformedCallPassesThrough(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{NameSuffix: "_x"},
		},
	}
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c"},{"id":"c2","function":{"name":5}}]}]}`)
	got, unmap, err := CloakTools(desc, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	// No client tools declared -> identity (nil unmap).
	if unmap != nil {
		t.Fatalf("unmap = %v, want nil", unmap)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body changed unexpectedly: %s", got)
	}
}

// TestCloakToolsNoToolsWithDecoys covers the isJSONNull + decoys branch.
func TestCloakToolsNoToolsWithDecoys(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{
				NameSuffix: "_x",
				DecoyTools: []contracts.ToolDecoy{{Name: "d1", Description: "n/a"}},
			},
		},
	}
	got, _, err := CloakTools(desc, []byte(`{"messages":[]}`))
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	if !bytes.Contains(got, []byte("d1")) {
		t.Fatalf("decoy not injected: %s", got)
	}
}

// TestCloakToolsNullToolsNoDecoys covers isJSONNull with no decoys (no change).
func TestCloakToolsNullToolsNoDecoys(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{NameSuffix: "_x"},
		},
	}
	body := []byte(`{"messages":[]}`)
	got, unmap, err := CloakTools(desc, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	if unmap != nil || !bytes.Equal(got, body) {
		t.Fatalf("got %s, %v", got, unmap)
	}
}

// --- identity values ---

// TestUserAgentIsDescriptorValue pins that UserAgent never fabricates.
func TestUserAgentIsDescriptorValue(t *testing.T) {
	ua := "antigravity/ide/2.11.0 darwin/arm64"
	desc := contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{UserAgent: ua}}
	if got := UserAgent(desc); got != ua {
		t.Fatalf("UserAgent = %q, want %q", got, ua)
	}
	if got := UserAgent(contracts.ProviderDescriptor{}); got != "" {
		t.Fatalf("empty descriptor UA = %q, want empty", got)
	}
}

// TestSyntheticProjectIsDeterministic is the core guarantee: same seed, same id;
// different seeds, different ids.
func TestSyntheticProjectIsDeterministic(t *testing.T) {
	first := SyntheticProject("seed-a")
	for i := 0; i < 50; i++ {
		if got := SyntheticProject("seed-a"); got != first {
			t.Fatalf("iteration %d: SyntheticProject drifted: %q vs %q", i, got, first)
		}
	}
	if SyntheticProject("seed-a") == SyntheticProject("seed-b") {
		t.Fatal("distinct seeds produced the same project id")
	}
	// The shape is adjective-noun-hex5.
	parts := 0
	for _, r := range first {
		if r == '-' {
			parts++
		}
	}
	if parts != 2 {
		t.Fatalf("project id %q does not have adjective-noun-suffix shape", first)
	}
}

// TestSyntheticProjectEmptySeedIsStable covers the empty-seed determinism.
func TestSyntheticProjectEmptySeedIsStable(t *testing.T) {
	first := SyntheticProject("")
	second := SyntheticProject("")
	if first != second {
		t.Fatal("empty seed is not stable")
	}
}

// --- purity ---

// TestPurityIsDeterministic runs every operation twice on the same input and
// asserts byte equality. A hidden clock or random would break this.
func TestPurityIsDeterministic(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			UserAgent:        "ua/1",
			PromptRewrites:   []contracts.PromptRewrite{{From: "a", To: "b"}, {From: `x(\d+)`, To: "y$1", IsRegex: true}},
			ToolCloaking:     &contracts.ToolCloaking{NameSuffix: "_z", DecoyTools: []contracts.ToolDecoy{{Name: "d", Description: "n/a"}}},
			SyntheticProject: true,
		},
	}
	body := []byte(`{"model":"m","messages":[{"role":"system","content":"a x1"}],"tools":[{"type":"function","function":{"name":"t"}}]}`)

	// Capture a reference on the first iteration and compare every later
	// iteration against it. Comparing two calls in the SAME iteration would be
	// flagged as a tautology (identical expressions), and would not prove
	// stability across runs anyway.
	var refApply, refCloak []byte
	var refUA, refProject string
	for i := 0; i < 20; i++ {
		a, _ := Apply(desc, body)
		c, _, _ := CloakTools(desc, body)
		ua := UserAgent(desc)
		p := SyntheticProject("s")
		if i == 0 {
			refApply, refCloak, refUA, refProject = a, c, ua, p
			continue
		}
		if !bytes.Equal(a, refApply) {
			t.Fatal("Apply is non-deterministic across calls")
		}
		if !bytes.Equal(c, refCloak) {
			t.Fatal("CloakTools is non-deterministic across calls")
		}
		if ua != refUA {
			t.Fatal("UserAgent is non-deterministic across calls")
		}
		if p != refProject {
			t.Fatal("SyntheticProject is non-deterministic across calls")
		}
	}
}

// --- contracts helpers ---

// TestIsObfuscated covers each field's contribution to the predicate.
func TestIsObfuscated(t *testing.T) {
	tests := []struct {
		name string
		desc contracts.ProviderDescriptor
		want bool
	}{
		{"empty", contracts.ProviderDescriptor{}, false},
		{"ua", contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{UserAgent: "x"}}, true},
		{"requires ua", contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{RequiresUserAgent: true}}, true},
		{"rewrites", contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{PromptRewrites: []contracts.PromptRewrite{{From: "a"}}}}, true},
		{"cloaking", contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{ToolCloaking: &contracts.ToolCloaking{}}}, true},
		{"project", contracts.ProviderDescriptor{Obfuscation: contracts.Obfuscation{SyntheticProject: true}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsObfuscated(); got != tt.want {
				t.Errorf("IsObfuscated() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestObfuscationErrorIsRequestScoped pins the ADR-0002 classification.
func TestObfuscationErrorIsRequestScoped(t *testing.T) {
	err := obfuscationError("reason", nil)
	de, ok := err.(*domain.DomainError)
	if !ok {
		t.Fatalf("err = %T", err)
	}
	if de.Code != domain.CodeInvalidRequest {
		t.Errorf("code = %q", de.Code)
	}
	if de.Scope != domain.ScopeRequest {
		t.Errorf("scope = %v, want request", de.Scope)
	}
}

// TestWireCloudCode pins the new wire format value (ADR-0003 §2: the CloudCode
// protocol is declared even though the executor lands in the next wave).
func TestWireCloudCode(t *testing.T) {
	if contracts.WireCloudCode != "cloudcode" {
		t.Fatalf("WireCloudCode = %q", contracts.WireCloudCode)
	}
}
