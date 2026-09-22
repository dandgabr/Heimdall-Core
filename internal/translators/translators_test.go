package translators

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestPurityIsDeterministic pins the purity invariant: the same input bytes
// produce the same output bytes, twice, with no hidden state. This is what makes
// the golden files meaningful. It runs every translator over every direction;
// a translator that introduced a clock or a random value would fail here.
func TestPurityIsDeterministic(t *testing.T) {
	req := []byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)
	anthFull := []byte(`{"id":"m1","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"yo"}],"stop_reason":"end_turn"}`)
	gemFull := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"yo"}]},"finishReason":"STOP"}]}`)
	anthChunk := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"a"}}`)
	gemChunk := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]}}]}`)

	type call struct {
		name string
		fn   func() ([]byte, error)
	}
	translations := []call{
		{"identity.Request", func() ([]byte, error) { return Identity{}.Request(req, "m", true) }},
		{"identity.ResponseFull", func() ([]byte, error) { return Identity{}.ResponseFull(anthFull, "m") }},
		{"identity.ResponseChunk", func() ([]byte, error) { return Identity{}.ResponseChunk(anthChunk, "m") }},
		{"anthropic.Request", func() ([]byte, error) { return AnthropicToOpenAI{}.Request(req, "m", false) }},
		{"anthropic.ResponseFull", func() ([]byte, error) { return AnthropicToOpenAI{}.ResponseFull(anthFull, "m") }},
		{"anthropic.ResponseChunk", func() ([]byte, error) { return AnthropicToOpenAI{}.ResponseChunk(anthChunk, "m") }},
		{"gemini.Request", func() ([]byte, error) { return GeminiToOpenAI{}.Request(req, "m", false) }},
		{"gemini.ResponseFull", func() ([]byte, error) { return GeminiToOpenAI{}.ResponseFull(gemFull, "m") }},
		{"gemini.ResponseChunk", func() ([]byte, error) { return GeminiToOpenAI{}.ResponseChunk(gemChunk, "m") }},
	}

	for _, c := range translations {
		t.Run(c.name, func(t *testing.T) {
			first, err := c.fn()
			if err != nil {
				t.Fatalf("first call: %v", err)
			}
			second, err := c.fn()
			if err != nil {
				t.Fatalf("second call: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("non-deterministic: %s vs %s", first, second)
			}
		})
	}
}

// TestIdentityReturnsDefensiveCopy proves the identity translator does not alias
// caller memory: mutating the input after the call must not change the output.
func TestIdentityReturnsDefensiveCopy(t *testing.T) {
	in := []byte(`{"model":"m","messages":[]}`)
	out, err := Identity{}.Request(in, "m", false)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	in[0] = 'X'
	if out[0] == 'X' {
		t.Fatal("identity output aliases caller input")
	}
}

// TestIdentityNilPassthrough covers copyBytes' nil branch.
func TestIdentityNilPassthrough(t *testing.T) {
	if got, err := (Identity{}).Request(nil, "m", false); err != nil || got != nil {
		t.Fatalf("Request(nil) = %v, %v", got, err)
	}
	if got, err := (Identity{}).ResponseFull(nil, "m"); err != nil || got != nil {
		t.Fatalf("ResponseFull(nil) = %v, %v", got, err)
	}
	if got, err := (Identity{}).ResponseChunk(nil, "m"); err != nil || got != nil {
		t.Fatalf("ResponseChunk(nil) = %v, %v", got, err)
	}
}
func TestFromToPairs(t *testing.T) {
	pairs := []struct {
		tr       contracts.Translator
		from, to contracts.WireFormat
	}{
		{Identity{}, contracts.WireOpenAI, contracts.WireOpenAI},
		{AnthropicToOpenAI{}, contracts.WireOpenAI, contracts.WireAnthropic},
		{GeminiToOpenAI{}, contracts.WireOpenAI, contracts.WireGemini},
	}
	for _, p := range pairs {
		if p.tr.From() != p.from || p.tr.To() != p.to {
			t.Errorf("%T: From/To = %s/%s, want %s/%s", p.tr, p.tr.From(), p.tr.To(), p.from, p.to)
		}
	}
}

// TestUnmappedCanonicalFieldsAreDropped documents the SUBSET boundary: a
// cross-format translator only carries the fields it models (docs/openai-compat.md).
// The identity translator, by contrast, preserves everything. These two
// assertions together are the contract for "unknown fields survive where it is
// lossless, and are dropped where the provider has no slot".
func TestUnmappedCanonicalFieldsAreDropped(t *testing.T) {
	canonical := []byte(`{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"logprobs":true,"top_logprobs":3,"logit_bias":{"1":2},"x_provider_extension":{"a":1}}`)

	// Anthropic: none of these map to the Messages API.
	got, err := AnthropicToOpenAI{}.Request(canonical, "m", false)
	if err != nil {
		t.Fatalf("anthropic Request: %v", err)
	}
	for _, dropped := range []string{"logprobs", "top_logprobs", "logit_bias", "x_provider_extension"} {
		if bytes.Contains(got, []byte(dropped)) {
			t.Errorf("anthropic output unexpectedly contains %q: %s", dropped, got)
		}
	}

	// Gemini: likewise.
	got, err = GeminiToOpenAI{}.Request(canonical, "m", false)
	if err != nil {
		t.Fatalf("gemini Request: %v", err)
	}
	for _, dropped := range []string{"logprobs", "top_logprobs", "logit_bias", "x_provider_extension"} {
		if bytes.Contains(got, []byte(dropped)) {
			t.Errorf("gemini output unexpectedly contains %q: %s", dropped, got)
		}
	}
}

// TestIdentityPreservesUnknownFields is the other half: the canonical pivot keeps
// a provider extension it does not model, because the identity translator copies
// bytes.
func TestIdentityPreservesUnknownFields(t *testing.T) {
	canonical := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"x_provider_extension":{"keep":true}}`)
	got, err := Identity{}.Request(canonical, "m", false)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !bytes.Contains(got, []byte("x_provider_extension")) {
		t.Fatalf("identity dropped an unknown field: %s", got)
	}
}

// TestRequestErrorPaths covers each decoder's failure branch with a malformed
// payload, asserting the typed translate.failed error.
func TestRequestErrorPaths(t *testing.T) {
	for _, tr := range []contracts.Translator{AnthropicToOpenAI{}, GeminiToOpenAI{}} {
		t.Run(string(tr.To()), func(t *testing.T) {
			_, err := tr.Request([]byte("{not json"), "m", false)
			assertCode(t, err, domain.CodeTranslateFailed)
		})
	}
}

// TestResponseFullErrorPaths covers the provider-payload decode failures, which
// are ScopeProvider (an upstream fault, not a client fault).
func TestResponseFullErrorPaths(t *testing.T) {
	for _, tr := range []contracts.Translator{AnthropicToOpenAI{}, GeminiToOpenAI{}} {
		_, err := tr.ResponseFull([]byte("oops"), "m")
		assertCode(t, err, domain.CodeTranslateFailed)
		de, _ := err.(*domain.DomainError)
		if de.Scope != domain.ScopeProvider {
			t.Errorf("%T: scope = %v, want provider", tr, de.Scope)
		}
		if _, err := tr.ResponseFull(nil, "m"); err == nil {
			t.Errorf("%T: empty payload accepted", tr)
		}
	}
}

// TestResponseChunkErrorPaths covers the chunk decode failure.
func TestResponseChunkErrorPaths(t *testing.T) {
	for _, tr := range []contracts.Translator{AnthropicToOpenAI{}, GeminiToOpenAI{}} {
		if _, err := tr.ResponseChunk([]byte("["), "m"); err == nil {
			t.Errorf("%T: malformed chunk accepted", tr)
		}
	}
}

// TestRequestContentErrorPaths covers splitContent's failure branches.
func TestRequestContentErrorPaths(t *testing.T) {
	bad := []string{
		`{"messages":[{"role":"user","content":123}]}`,
		`{"messages":[{"role":"user","content":[{"type":"text","text":5}]}]}`,
	}
	for _, body := range bad {
		for _, tr := range []contracts.Translator{AnthropicToOpenAI{}, GeminiToOpenAI{}} {
			if _, err := tr.Request([]byte(body), "m", false); err == nil {
				t.Errorf("%T: bad content accepted: %s", tr, body)
			}
		}
	}
}

// TestRequestMissingModelUsesArg covers the model-resolution fallback: when the
// caller supplies no model, only Anthropic/Gemini read it from the payload.
func TestRequestModelFallback(t *testing.T) {
	canonical := []byte(`{"model":"from-body","max_tokens":1,"messages":[{"role":"user","content":"x"}]}`)

	anth, err := AnthropicToOpenAI{}.Request(canonical, "", false)
	if err != nil {
		t.Fatalf("anthropic: %v", err)
	}
	assertJSONField(t, anth, "model", "from-body")

	gem, err := GeminiToOpenAI{}.Request(canonical, "", false)
	if err != nil {
		t.Fatalf("gemini: %v", err)
	}
	// Gemini places the model outside the body; assert it did not error and the
	// content is present.
	if !bytes.Contains(gem, []byte(`"contents"`)) {
		t.Fatalf("gemini output missing contents: %s", gem)
	}
}

// TestResponseFullModelFallback covers the model fallback on the response side.
func TestResponseFullModelFallback(t *testing.T) {
	anth := []byte(`{"id":"m1","type":"message","role":"assistant","model":"claude-x","content":[{"type":"text","text":"y"}],"stop_reason":"end_turn"}`)
	out, err := AnthropicToOpenAI{}.ResponseFull(anth, "")
	if err != nil {
		t.Fatalf("anthropic: %v", err)
	}
	assertJSONField(t, out, "model", "claude-x")

	gem := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"y"}]}}],"modelVersion":"gemini-x"}`)
	out, err = GeminiToOpenAI{}.ResponseFull(gem, "")
	if err != nil {
		t.Fatalf("gemini: %v", err)
	}
	assertJSONField(t, out, "model", "gemini-x")
}

// TestToolChoiceVariants covers the tool_choice mapping branches.
func TestToolChoiceVariants(t *testing.T) {
	base := `"messages":[{"role":"user","content":"x"}],"max_tokens":8`

	t.Run("anthropic auto", func(t *testing.T) {
		out, err := AnthropicToOpenAI{}.Request(reqWith(base, `"auto"`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "tool_choice.type", "auto") // helper handles nested
	})
	t.Run("anthropic none", func(t *testing.T) {
		out, err := AnthropicToOpenAI{}.Request(reqWith(base, `"none"`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if bytes.Contains(out, []byte("tool_choice")) {
			t.Errorf("none should drop tool_choice: %s", out)
		}
	})
	t.Run("anthropic named", func(t *testing.T) {
		out, err := AnthropicToOpenAI{}.Request(reqWith(base, `{"type":"function","function":{"name":"f"}}`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "tool_choice.name", "f")
	})
	t.Run("gemini none", func(t *testing.T) {
		out, err := GeminiToOpenAI{}.Request(reqWith(base, `"none"`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "toolConfig.functionCallingConfig.mode", "NONE")
	})
	t.Run("gemini auto", func(t *testing.T) {
		out, err := GeminiToOpenAI{}.Request(reqWith(base, `"auto"`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "toolConfig.functionCallingConfig.mode", "AUTO")
	})
	t.Run("gemini required", func(t *testing.T) {
		out, err := GeminiToOpenAI{}.Request(reqWith(base, `"required"`), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "toolConfig.functionCallingConfig.mode", "ANY")
	})
}

// TestMaxCompletionTokensFallback covers the max_completion_tokens branch.
func TestMaxCompletionTokensFallback(t *testing.T) {
	body := []byte(`{"model":"m","max_completion_tokens":77,"messages":[{"role":"user","content":"x"}]}`)
	out, err := AnthropicToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "max_tokens", float64(77))

	out, err = GeminiToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "generationConfig.maxOutputTokens", float64(77))
}

// TestStringOrSliceVariants covers the stop-as-string and stop-as-array decode.
func TestStringOrSliceVariants(t *testing.T) {
	scalar := []byte(`{"model":"m","max_tokens":1,"stop":"ONE","messages":[{"role":"user","content":"x"}]}`)
	out, err := AnthropicToOpenAI{}.Request(scalar, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "stop_sequences.0", "ONE")

	array := []byte(`{"model":"m","max_tokens":1,"stop":["A","B"],"messages":[{"role":"user","content":"x"}]}`)
	out, err = AnthropicToOpenAI{}.Request(array, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "stop_sequences.1", "B")

	// null stop decodes to nil and is omitted.
	nullStop := []byte(`{"model":"m","max_tokens":1,"stop":null,"messages":[{"role":"user","content":"x"}]}`)
	out, err = AnthropicToOpenAI{}.Request(nullStop, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if bytes.Contains(out, []byte("stop_sequences")) {
		t.Errorf("null stop produced stop_sequences: %s", out)
	}

	// A malformed stop (number) fails.
	if _, err := (AnthropicToOpenAI{}).Request([]byte(`{"model":"m","stop":5,"messages":[]}`), "m", false); err == nil {
		t.Error("numeric stop accepted")
	}
}

// TestAnthropicSystemOnly covers the case where the request has only a system
// message: it becomes the top-level system field and the messages array stays
// empty (no fabricated turn).
func TestAnthropicSystemOnly(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"system","content":"rules"}]}`)
	out, err := AnthropicToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "system", "rules")
	// messages is present but empty: an empty array, not a role-only turn.
	assertJSONField(t, out, "messages", []any{})
}

// TestAnthropicRoleOnlyTurn covers faithful mapping of an empty-content turn:
// the translator emits an empty content array rather than inventing a text
// block. Upstream validation is the provider's job, not the translator's.
func TestAnthropicRoleOnlyTurn(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":""}]}`)
	out, err := AnthropicToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "messages.0.content", []any{})
}

// TestGeminiRoleOnlyTurn covers the same faithful mapping for Gemini.
func TestGeminiRoleOnlyTurn(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":""}]}`)
	out, err := GeminiToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "contents.0.parts", []any{})
}

// TestGeminiNoGenerationConfig covers the all-nil generationConfig branch.
func TestGeminiNoGenerationConfig(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	out, err := GeminiToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if bytes.Contains(out, []byte("generationConfig")) {
		t.Errorf("no generation fields produced generationConfig: %s", out)
	}
}

// TestAnthropicUnknownStreamEvents covers the default and nil-delta guards.
func TestAnthropicUnknownStreamEvents(t *testing.T) {
	for _, payload := range []string{
		`{"type":"content_block_delta","delta":{"type":"thinking_delta"}}`,
		`{"type":"content_block_delta"}`,
		`{"type":"content_block_start","content_block":{"type":"text"}}`,
		`{"type":"totally_unknown"}`,
		`{"type":"message_stop"}`,
	} {
		out, err := AnthropicToOpenAI{}.ResponseChunk([]byte(payload), "m")
		if err != nil {
			t.Fatalf("%s: %v", payload, err)
		}
		if out != nil {
			t.Errorf("%s: expected nil (nothing to emit), got %s", payload, out)
		}
	}
}

// TestGeminiEmptyFrameReturnsNil covers the "noise frame" branch that must emit
// nothing rather than an empty chunk.
func TestGeminiEmptyFrameReturnsNil(t *testing.T) {
	out, err := GeminiToOpenAI{}.ResponseChunk([]byte(`{"candidates":[{"content":{"role":"model","parts":[]}}]}`), "m")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if out != nil {
		t.Errorf("empty frame emitted %s", out)
	}
}

// TestImageSourceVariants covers data-URL and plain-URL image mapping plus the
// malformed data-URL fallback.
func TestImageSourceVariants(t *testing.T) {
	t.Run("anthropic data url", func(t *testing.T) {
		out, err := AnthropicToOpenAI{}.Request(multimodalReq("data:image/png;base64,AAAB"), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "messages.0.content.0.source.type", "base64")
		assertJSONField(t, out, "messages.0.content.0.source.data", "AAAB")
	})
	t.Run("anthropic plain url", func(t *testing.T) {
		out, err := AnthropicToOpenAI{}.Request(multimodalReq("https://x/a.jpg"), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "messages.0.content.0.source.type", "url")
	})
	t.Run("anthropic malformed data url", func(t *testing.T) {
		// data: without ;base64, -> falls back to the url form.
		out, err := AnthropicToOpenAI{}.Request(multimodalReq("data:image/png,AAAB"), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "messages.0.content.0.source.type", "url")
	})
	t.Run("gemini data url", func(t *testing.T) {
		out, err := GeminiToOpenAI{}.Request(multimodalReq("data:image/png;base64,AAAB"), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "contents.0.parts.0.inlineData.mimeType", "image/png")
	})
	t.Run("gemini plain url", func(t *testing.T) {
		out, err := GeminiToOpenAI{}.Request(multimodalReq("https://x/a.jpg"), "m", false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		assertJSONField(t, out, "contents.0.parts.0.fileData.fileUri", "https://x/a.jpg")
	})
}

// --- helpers ---

// TestFinishReasonMappings covers every branch of both finish-reason mappers.
func TestFinishReasonMappings(t *testing.T) {
	anth := map[string]string{
		"end_turn":      "stop",
		"max_tokens":    "length",
		"tool_use":      "tool_calls",
		"stop_sequence": "stop",
		"":              "",
		"weird":         "weird",
	}
	for in, want := range anth {
		if got := anthropicFinishReason(in); got != want {
			t.Errorf("anthropicFinishReason(%q) = %q, want %q", in, got, want)
		}
	}
	gem := map[string]string{
		"STOP":               "stop",
		"MAX_TOKENS":         "length",
		"SAFETY":             "content_filter",
		"RECITATION":         "content_filter",
		"BLOCKLIST":          "content_filter",
		"PROHIBITED_CONTENT": "content_filter",
		"SPII":               "content_filter",
		"":                   "",
		"OTHER":              "OTHER",
	}
	for in, want := range gem {
		if got := geminiFinishReason(in); got != want {
			t.Errorf("geminiFinishReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStringOrSliceMarshal covers the nil and non-nil MarshalJSON branches
// directly (the encoders exercise the non-nil path, but not the nil one).
func TestStringOrSliceMarshal(t *testing.T) {
	var nilStop stringOrSlice
	b, err := nilStop.MarshalJSON()
	if err != nil || string(b) != "null" {
		t.Fatalf("nil MarshalJSON = %s, %v", b, err)
	}
	b, err = stringOrSlice{"a", "b"}.MarshalJSON()
	if err != nil || string(b) != `["a","b"]` {
		t.Fatalf("MarshalJSON = %s, %v", b, err)
	}
}

// TestAnthropicToolUseWithoutID covers toAnthropicBlocks' empty-arguments
// fallback and a tool call with no id.
func TestAnthropicToolUseEmptyArguments(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":4,"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f"}}]}]}`)
	out, err := AnthropicToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "messages.0.content.0.input", map[string]any{})
	assertJSONField(t, out, "messages.0.content.0.type", "tool_use")
}

// TestAnthropicParallelToolCallIndex is the P3 regression: parallel tool calls
// must carry the Anthropic content-block index, so a client that reassembles
// deltas by tool_calls[].index does not merge two calls into one. Before the fix
// both start and delta frames emitted Index 0.
func TestAnthropicParallelToolCallIndex(t *testing.T) {
	start := []byte(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_2","name":"get_forecast"}}`)
	out, err := AnthropicToOpenAI{}.ResponseChunk(start, "m")
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "choices.0.delta.tool_calls.0.index", float64(1))
	assertJSONField(t, out, "choices.0.delta.tool_calls.0.id", "toolu_2")

	delta := []byte(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"days\":3}"}}`)
	out, err = AnthropicToOpenAI{}.ResponseChunk(delta, "m")
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "choices.0.delta.tool_calls.0.index", float64(1))
	// The two parallel calls must be distinguishable: index 0 and 1 differ.
	first := []byte(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather"}}`)
	out0, err := AnthropicToOpenAI{}.ResponseChunk(first, "m")
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out0, "choices.0.delta.tool_calls.0.index", float64(0))
}

// TestSplitDataURLMalformed covers the no-comma and non-base64 branches.
func TestSplitDataURLMalformed(t *testing.T) {
	cases := []string{
		"data:image/png;base64", // no comma
		"data:image/png,AAAA",   // not base64
		"https://x/a.jpg",       // not a data url
	}
	for _, raw := range cases {
		if media, data, ok := splitDataURL(raw); ok {
			t.Errorf("splitDataURL(%q) = %q,%q,true; want false", raw, media, data)
		}
	}
	if media, data, ok := splitDataURL("data:image/png;base64,AAAB"); !ok || media != "image/png" || data != "AAAB" {
		t.Errorf("valid data url = %q,%q,%v", media, data, ok)
	}
}

// TestToAnthropicToolChoiceMalformed covers the unmarshal-failure and
// non-matching branches of the tool_choice mapper.
func TestToAnthropicToolChoiceMalformed(t *testing.T) {
	for _, raw := range []string{`123`, `{"type":"other"}`, `{"type":"function"}`, `"bogus"`} {
		if got := toAnthropicToolChoice(json.RawMessage(raw)); got != nil {
			t.Errorf("toAnthropicToolChoice(%s) = %+v, want nil", raw, got)
		}
	}
}

// TestToGeminiToolConfigMalformed covers the same branches for Gemini.
func TestToGeminiToolConfigMalformed(t *testing.T) {
	for _, raw := range []string{`123`, `{"type":"other"}`, `"bogus"`} {
		if got := toGeminiToolConfig(json.RawMessage(raw)); got != nil {
			t.Errorf("toGeminiToolConfig(%s) = %+v, want nil", raw, got)
		}
	}
}

// TestCompactRawFallbacks covers compactRaw's invalid-JSON and null branches.
func TestCompactRawFallbacks(t *testing.T) {
	if got := compactRaw(nil, "{}"); got != "{}" {
		t.Errorf("nil = %q, want {}", got)
	}
	if got := compactRaw(json.RawMessage("null"), "{}"); got != "{}" {
		t.Errorf("null = %q, want {}", got)
	}
	if got := compactRaw(json.RawMessage("{bad"), "{}"); got != "{bad" {
		t.Errorf("invalid = %q, want raw passthrough", got)
	}
	if got := compactRaw(json.RawMessage(`{ "a" : 1 }`), "{}"); got != `{"a":1}` {
		t.Errorf("whitespace = %q, want compact", got)
	}
}

// TestNormalizeRaw covers both branches.
func TestNormalizeRaw(t *testing.T) {
	if got := normalizeRaw(nil, "{}"); string(got) != "{}" {
		t.Errorf("nil = %s", got)
	}
	if got := normalizeRaw(json.RawMessage(`{"a":1}`), "{}"); string(got) != `{"a":1}` {
		t.Errorf("value = %s", got)
	}
}

// TestMustJSONPanics covers the panic branch with an unmarshalable value.
func TestMustJSONPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustJSON did not panic on an unmarshalable value")
		}
	}()
	mustJSON(func() {})
}

// TestTrimSpaceCoversAllWhitespace covers leading/trailing whitespace trimming.
func TestTrimSpace(t *testing.T) {
	got := trimSpace([]byte("  \t\n x \r\n "))
	if string(got) != "x" {
		t.Errorf("trimSpace = %q", got)
	}
	if got := trimSpace([]byte("   ")); len(got) != 0 {
		t.Errorf("all-space = %q", got)
	}
}

// TestFormatsEmpty covers Formats on an empty registry.
func TestFormatsEmpty(t *testing.T) {
	if got := NewRegistry().Formats(); len(got) != 0 {
		t.Errorf("Formats() = %v, want empty", got)
	}
}

// TestMalformedJSONStartingWithQuote covers the UnmarshalJSON error branch in
// stringOrSlice and splitContent (an input whose first byte is a quote but which
// is not a valid JSON string).
func TestMalformedJSONStartingWithQuote(t *testing.T) {
	var s stringOrSlice
	if err := s.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Error("stringOrSlice accepted a malformed string")
	}
	if _, err := splitContent(json.RawMessage(`"unterminated`)); err == nil {
		t.Error("splitContent accepted a malformed string")
	}
}

// TestToToolChoiceUnmarshalFailure covers the json.Unmarshal failure branch for
// a quote-prefixed but invalid tool_choice.
func TestToToolChoiceUnmarshalFailure(t *testing.T) {
	if got := toAnthropicToolChoice(json.RawMessage(`"bad`)); got != nil {
		t.Errorf("anthropic = %+v, want nil", got)
	}
	if got := toGeminiToolConfig(json.RawMessage(`"bad`)); got != nil {
		t.Errorf("gemini = %+v, want nil", got)
	}
}

// TestGeminiRequestAssistantToolCalls covers toGeminiParts' function-call branch
// (an assistant turn with tool_calls).
func TestGeminiRequestAssistantToolCalls(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":4,"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]}]}`)
	out, err := GeminiToOpenAI{}.Request(body, "m", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assertJSONField(t, out, "contents.0.parts.0.functionCall.name", "f")
}

// TestRegistryPairsSortAcrossFormats covers the Pairs comparator's `from`
// branch and the Formats comparator, which need more than one source format.
func TestRegistryPairsSortAcrossFormats(t *testing.T) {
	r := NewRegistry()
	// Two pairs from openai (differs in `to`) and one from anthropic (differs in
	// `from`), registered out of order.
	for _, tr := range []contracts.Translator{
		AnthropicToOpenAI{}, // openai -> anthropic
		Identity{},          // openai -> openai
		crossFormatTranslator{from: contracts.WireAnthropic, to: contracts.WireGemini},
	} {
		if err := r.Register(tr); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	pairs := r.Pairs()
	want := [][2]contracts.WireFormat{
		{contracts.WireAnthropic, contracts.WireGemini},
		{contracts.WireOpenAI, contracts.WireAnthropic},
		{contracts.WireOpenAI, contracts.WireOpenAI},
	}
	if len(pairs) != len(want) {
		t.Fatalf("Pairs = %v, want %v", pairs, want)
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Fatalf("Pairs[%d] = %v, want %v", i, pairs[i], want[i])
		}
	}
	formats := r.Formats()
	if len(formats) != 2 || formats[0] != contracts.WireAnthropic || formats[1] != contracts.WireOpenAI {
		t.Fatalf("Formats = %v, want [anthropic openai]", formats)
	}
}

// crossFormatTranslator is a test-only translator with arbitrary formats, used
// to exercise the registry's ordering with more than one source format.
type crossFormatTranslator struct{ from, to contracts.WireFormat }

func (t crossFormatTranslator) From() contracts.WireFormat { return t.from }
func (t crossFormatTranslator) To() contracts.WireFormat   { return t.to }
func (crossFormatTranslator) Request(b []byte, _ string, _ bool) ([]byte, error) {
	return b, nil
}
func (crossFormatTranslator) ResponseFull(b []byte, _ string) ([]byte, error) { return b, nil }
func (crossFormatTranslator) ResponseChunk(b []byte, _ string) ([]byte, error) {
	return b, nil
}

// --- helpers ---

func reqWith(base, toolChoice string) []byte {
	return []byte(`{"model":"m","tool_choice":` + toolChoice + `,` + base + `}`)
}

func multimodalReq(url string) []byte {
	return []byte(`{"model":"m","max_tokens":4,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"` + url + `"}}]}]}`)
}

// assertJSONField decodes body and asserts a dotted path equals want.
func assertJSONField(t *testing.T, body []byte, path string, want any) {
	t.Helper()
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("assertJSONField: %v (%s)", err, body)
	}
	cur := root
	for _, seg := range splitDots(path) {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				t.Fatalf("path %q: key %q missing in %s", path, seg, body)
			}
			cur = v
		case []any:
			var idx int
			if _, err := fmtSscan(seg, &idx); err != nil || idx < 0 || idx >= len(node) {
				t.Fatalf("path %q: index %q invalid", path, seg)
			}
			cur = node[idx]
		default:
			t.Fatalf("path %q: cannot descend into %T", path, cur)
		}
	}
	if !reflect.DeepEqual(cur, want) {
		t.Errorf("path %q = %#v, want %#v (body %s)", path, cur, want, body)
	}
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errNotAnIndex
		}
		n = n*10 + int(s[i]-'0')
	}
	*out = n
	return 1, nil
}

var errNotAnIndex = errString("not an index")

type errString string

func (e errString) Error() string { return string(e) }

// assertCode asserts err is a DomainError with the given code.
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	de, ok := err.(*domain.DomainError)
	if !ok {
		t.Fatalf("err = %v (%T), want *domain.DomainError", err, err)
	}
	if de.Code != code {
		t.Fatalf("code = %q, want %q", de.Code, code)
	}
}
