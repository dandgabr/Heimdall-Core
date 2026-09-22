package translators

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file is the executable half of docs/openai-compat.md. It pins the two
// properties the document promises:
//
//  1. The canonical OpenAI path (identity translator) preserves unknown fields
//     and streaming structure byte-for-byte, because it copies bytes.
//  2. The cross-format translators drop only what they do not model, and the
//     drop is enumerated (not accidental).

// TestCompatUnknownRequestFieldsPreservedByIdentity is the round-trip guarantee:
// a request carrying provider extensions (or newer OpenAI fields) survives the
// identity translator unchanged.
func TestCompatUnknownRequestFieldsPreservedByIdentity(t *testing.T) {
	canonical := []byte(`{
		"model":"gpt-4o",
		"messages":[{"role":"user","content":"hi"}],
		"response_format":{"type":"json_object"},
		"seed":42,
		"logprobs":true,
		"n":2,
		"x_future_openai_field":{"nested":true},
		"x_vendor_extension":[1,2,3]
	}`)

	out, err := Identity{}.Request(canonical, "gpt-4o", false)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	// The bytes must be identical: byte preservation is the point.
	if !bytes.Equal(out, canonical) {
		t.Fatalf("identity did not preserve the request byte-for-byte\n in: %s\nout: %s", canonical, out)
	}
}

// TestCompatUnknownResponseFieldsPreservedByIdentity covers the response side of
// the same guarantee.
func TestCompatUnknownResponseFieldsPreservedByIdentity(t *testing.T) {
	payload := []byte(`{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"system_fingerprint":"fp_x","x_extra":"kept"}`)
	out, err := Identity{}.ResponseFull(payload, "m")
	if err != nil {
		t.Fatalf("ResponseFull: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("identity did not preserve the response\n in: %s\nout: %s", payload, out)
	}

	chunk := []byte(`{"id":"c1","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"content":"a"},"finish_reason":null}],"x_extra":"kept"}`)
	out, err = Identity{}.ResponseChunk(chunk, "m")
	if err != nil {
		t.Fatalf("ResponseChunk: %v", err)
	}
	if !bytes.Equal(out, chunk) {
		t.Fatalf("identity did not preserve the chunk\n in: %s\nout: %s", chunk, out)
	}
}

// TestCompatToolCallFragmentsAreNotReassembled pins the streaming guarantee from
// docs/openai-compat.md: an Anthropic input_json_delta frame becomes a
// tool_calls argument fragment, forwarded as-is. The translator must not buffer
// or merge it with the id/name frame.
func TestCompatToolCallFragmentsAreNotReassembled(t *testing.T) {
	// Two separate frames: the id/name frame, then an argument fragment frame.
	start := []byte(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather"}}`)
	frag := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"SP\"}"}}`)

	outStart, err := AnthropicToOpenAI{}.ResponseChunk(start, "m")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	outFrag, err := AnthropicToOpenAI{}.ResponseChunk(frag, "m")
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}

	// The start frame carries id + name and NO arguments.
	startDoc := decodeChunk(t, outStart)
	if got := startDoc.Choices[0].Delta.ToolCalls[0].Function.Name; got != "get_weather" {
		t.Errorf("start frame name = %q", got)
	}
	if got := startDoc.Choices[0].Delta.ToolCalls[0].Function.Arguments; got != "" {
		t.Errorf("start frame unexpectedly carried arguments %q", got)
	}

	// The fragment frame carries ONLY the partial arguments; it must not repeat
	// the id or the name, and must not be merged into the previous frame.
	fragDoc := decodeChunk(t, outFrag)
	call := fragDoc.Choices[0].Delta.ToolCalls[0]
	if call.Function.Arguments != `{"city":"SP"}` {
		t.Errorf("fragment arguments = %q", call.Function.Arguments)
	}
	if call.ID != "" || call.Function.Name != "" {
		t.Errorf("fragment reintroduced id/name: %+v", call)
	}
}

// TestCompatUsageInFinalChunk pins that provider usage lands on the terminal
// chunk and is not dropped.
func TestCompatUsageInFinalChunk(t *testing.T) {
	anth := []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}`)
	out, err := AnthropicToOpenAI{}.ResponseChunk(anth, "m")
	if err != nil {
		t.Fatalf("anthropic: %v", err)
	}
	doc := decodeChunk(t, out)
	if doc.Usage == nil || doc.Usage.CompletionTokens != 15 {
		t.Errorf("anthropic final usage = %+v", doc.Usage)
	}
	if doc.Choices[0].FinishReason != "stop" {
		t.Errorf("anthropic finish = %q", doc.Choices[0].FinishReason)
	}

	gem := []byte(`{"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":2,"totalTokenCount":6}}`)
	out, err = GeminiToOpenAI{}.ResponseChunk(gem, "m")
	if err != nil {
		t.Fatalf("gemini: %v", err)
	}
	doc = decodeChunk(t, out)
	if doc.Usage == nil || doc.Usage.PromptTokens != 4 || doc.Usage.TotalTokens != 6 {
		t.Errorf("gemini final usage = %+v", doc.Usage)
	}
}

// TestCompatUnsupportedFieldsAreDocumented pins each field the document marks N
// or P-as-dropped: it must not appear in the cross-format output. This is the
// executable counterpart of the table in docs/openai-compat.md.
func TestCompatUnsupportedFieldsAreDocumented(t *testing.T) {
	// Every field the doc says is dropped by cross-format translators.
	canonical := []byte(`{
		"model":"m","max_tokens":8,
		"messages":[{"role":"user","content":"x"}],
		"n":2,"seed":42,"logprobs":true,"top_logprobs":3,"logit_bias":{"1":2},
		"frequency_penalty":0.5,"presence_penalty":0.5,"user":"u",
		"parallel_tool_calls":false,"response_format":{"type":"json_object"},
		"x_vendor":{"a":1}
	}`)
	dropped := []string{
		"n", "seed", "logprobs", "top_logprobs", "logit_bias",
		"frequency_penalty", "presence_penalty", "user",
		"parallel_tool_calls", "response_format", "x_vendor",
	}
	for _, tr := range []contracts.Translator{AnthropicToOpenAI{}, GeminiToOpenAI{}} {
		out, err := tr.Request(canonical, "m", false)
		if err != nil {
			t.Fatalf("%T: %v", tr, err)
		}
		for _, field := range dropped {
			// Match the JSON KEY form ("field":), not the bare word: "user" is
			// also a role VALUE ("role":"user"), and a bare substring match
			// would confuse the two.
			if bytes.Contains(out, []byte(`"`+field+`":`)) {
				t.Errorf("%T: field %q unexpectedly present (doc says dropped): %s", tr, field, out)
			}
		}
	}
}

// TestCompatSupportedFieldsSurviveRequest pins the fields the document marks S:
// they must appear in the cross-format request.
func TestCompatSupportedFieldsSurviveRequest(t *testing.T) {
	canonical := []byte(`{"model":"m","max_tokens":9,"temperature":0.3,"top_p":0.9,"stop":["Z"],"messages":[{"role":"user","content":"x"}]}`)

	anth, err := AnthropicToOpenAI{}.Request(canonical, "m", false)
	if err != nil {
		t.Fatalf("anthropic: %v", err)
	}
	for _, want := range []string{`"max_tokens"`, `"temperature"`, `"top_p"`, `"stop_sequences"`} {
		if !bytes.Contains(anth, []byte(want)) {
			t.Errorf("anthropic request missing %s: %s", want, anth)
		}
	}

	gem, err := GeminiToOpenAI{}.Request(canonical, "m", false)
	if err != nil {
		t.Fatalf("gemini: %v", err)
	}
	for _, want := range []string{`"maxOutputTokens"`, `"temperature"`, `"topP"`, `"stopSequences"`} {
		if !bytes.Contains(gem, []byte(want)) {
			t.Errorf("gemini request missing %s: %s", want, gem)
		}
	}
}

// --- decode helper ---

type chunkDoc struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func decodeChunk(t *testing.T, raw []byte) chunkDoc {
	t.Helper()
	var d chunkDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("decode chunk %s: %v", raw, err)
	}
	return d
}
