package translators

import (
	"encoding/json"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file holds the canonical (pivot) request/response shapes and the OpenAI
// identity translator.
//
// The pivot is OpenAI-shaped JSON (contracts.CanonicalFormat). The OpenAI family
// speaks the pivot natively, so its translator is the IDENTITY: every method
// returns its input bytes unchanged. That is not a stub — it is the correct
// behaviour, and it is why the common path has nothing to get wrong. The
// pipeline skips the call entirely via contracts.IsIdentity.

// Canonical request and response shapes. They are the decode target for the
// cross-format translators (anthropic.go, gemini.go); the field set is the
// SUBSET the gateway guarantees to translate (see docs/openai-compat.md). Any
// canonical field outside this set is not translated by a cross-format
// translator (documented and tested in TestCrossFormatDropsUnmappedFields);
// the identity translator preserves everything because it copies bytes.

// canonicalRequest is the pivot chat-completions request.
type canonicalRequest struct {
	Model               string          `json:"model"`
	Messages            []canonicalMsg  `json:"messages"`
	Tools               []canonicalTool `json:"tools,omitempty"`
	ToolChoice          json.RawMessage `json:"tool_choice,omitempty"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                stringOrSlice   `json:"stop,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	N                   *int            `json:"n,omitempty"`
	ResponseFormat      json.RawMessage `json:"response_format,omitempty"`
	Seed                *int            `json:"seed,omitempty"`
	ParallelToolCalls   *bool           `json:"parallel_tool_calls,omitempty"`
	StreamOptions       *streamOptions  `json:"stream_options,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	User                string          `json:"user,omitempty"`
	Logprobs            *bool           `json:"logprobs,omitempty"`
	TopLogprobs         *int            `json:"top_logprobs,omitempty"`
}

// streamOptions is the OpenAI stream_options object. include_usage is the field
// the gateway honours: it requests a final usage-only chunk.
type streamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// canonicalMsg is one pivot message.
type canonicalMsg struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"`
	ToolCalls  []canonicalTool `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
}

// canonicalTool is an OpenAI function tool OR a tool call. The two shapes share
// the function sub-object, so one type decodes both; the surrounding context
// (Tools vs ToolCalls) says which it is.
type canonicalTool struct {
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Function canonicalFunction `json:"function"`
}

type canonicalFunction struct {
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Arguments   string          `json:"arguments,omitempty"`
}

// canonicalPart is one content part of a multimodal pivot message.
type canonicalPart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	ImageURL *canonicalImage `json:"image_url,omitempty"`
}

type canonicalImage struct {
	URL string `json:"url"`
}

// canonicalResponse is the pivot non-streaming response.
type canonicalResponse struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []canonicalChoice `json:"choices"`
	Usage   *canonicalUsage   `json:"usage,omitempty"`
}

type canonicalChoice struct {
	Index        int          `json:"index"`
	Message      canonicalMsg `json:"message"`
	FinishReason string       `json:"finish_reason"`
}

type canonicalUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Identity is the OpenAI-family translator. From == To == WireOpenAI, so every
// method is a pass-through: the canonical payload already IS the OpenAI wire
// format. contracts.IsIdentity reports true, letting the pipeline skip it.
type Identity struct{}

// compile-time assertion against the frozen contract.
var _ contracts.Translator = Identity{}

// From implements contracts.Translator.
func (Identity) From() contracts.WireFormat { return contracts.WireOpenAI }

// To implements contracts.Translator.
func (Identity) To() contracts.WireFormat { return contracts.WireOpenAI }

// Request returns the canonical request verbatim.
func (Identity) Request(canonical []byte, _ string, _ bool) ([]byte, error) {
	return copyBytes(canonical), nil
}

// ResponseFull returns the provider response verbatim (already canonical).
func (Identity) ResponseFull(payload []byte, _ string) ([]byte, error) {
	return copyBytes(payload), nil
}

// ResponseChunk returns the provider stream frame verbatim (already canonical).
func (Identity) ResponseChunk(payload []byte, _ string) ([]byte, error) {
	return copyBytes(payload), nil
}

// copyBytes returns a defensive copy so a caller cannot mutate the translator's
// input through the returned slice, and the translator's output never aliases
// caller memory.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
