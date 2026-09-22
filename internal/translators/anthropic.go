package translators

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// AnthropicToOpenAI translates between the canonical OpenAI pivot and the
// Anthropic Messages API. From is the pivot, To is Anthropic, matching the
// contract's direction convention.
//
// Anthropic shape differences the translator handles:
//   - the system prompt is a TOP-LEVEL field, not a message;
//   - max_tokens is REQUIRED (the pivot makes it optional);
//   - content is an array of typed blocks (text / image / tool_use / tool_result)
//     rather than a string or OpenAI content parts;
//   - tools use a top-level input_schema and tool calls are tool_use blocks;
//   - streaming uses a named-event SSE protocol (message_start, content_block_*,
//     message_delta, message_stop) that is projected onto OpenAI choice deltas.
type AnthropicToOpenAI struct{}

var _ contracts.Translator = AnthropicToOpenAI{}

// From implements contracts.Translator.
func (AnthropicToOpenAI) From() contracts.WireFormat { return contracts.WireOpenAI }

// To implements contracts.Translator.
func (AnthropicToOpenAI) To() contracts.WireFormat { return contracts.WireAnthropic }

// anthropicMaxTokensDefault is the fallback for the required Anthropic
// max_tokens when the canonical request omitted it. The value is the largest
// single completion Anthropic accepts on its current models; a caller that needs
// a different bound sets max_tokens explicitly.
const anthropicMaxTokensDefault = 4096

// --- Anthropic wire types ---

type anthRequest struct {
	Model         string          `json:"model"`
	System        json.RawMessage `json:"system,omitempty"`
	Messages      []anthMessage   `json:"messages"`
	MaxTokens     int             `json:"max_tokens"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
	Tools         []anthTool      `json:"tools,omitempty"`
	ToolChoice    *anthToolChoice `json:"tool_choice,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
}

type anthMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthBlock struct {
	Type string `json:"type"`
	// text block
	Text string `json:"text,omitempty"`
	// image block
	Source *anthImageSource `json:"source,omitempty"`
	// tool_use block
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// tool_result block
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type anthImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

type anthTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// anthResponse is a non-streaming Messages response.
type anthResponse struct {
	ID         string      `json:"id"`
	Type       string      `json:"type"`
	Role       string      `json:"role"`
	Model      string      `json:"model"`
	Content    []anthBlock `json:"content"`
	StopReason string      `json:"stop_reason"`
	Usage      *anthUsage  `json:"usage,omitempty"`
}

type anthUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// anthStreamEvent is one Anthropic SSE event (the JSON part; the event name is
// carried in the "type" field as well).
type anthStreamEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index,omitempty"`
	Message *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage *struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage,omitempty"`
	} `json:"message,omitempty"`
	ContentBlock *struct {
		Type  string          `json:"type"`
		ID    string          `json:"id,omitempty"`
		Name  string          `json:"name,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	} `json:"content_block,omitempty"`
	Delta *struct {
		Type        string `json:"type"`
		Text        string `json:"text,omitempty"`
		PartialJSON string `json:"partial_json,omitempty"`
		StopReason  string `json:"stop_reason,omitempty"`
	} `json:"delta,omitempty"`
	Usage *anthUsage `json:"usage,omitempty"`
}

// --- Request: pivot -> Anthropic ---

// Request implements contracts.Translator.
func (AnthropicToOpenAI) Request(canonical []byte, model string, stream bool) ([]byte, error) {
	var req canonicalRequest
	if err := decodeJSON(canonical, &req); err != nil {
		return nil, err
	}
	if model == "" {
		model = req.Model
	}

	out := anthRequest{
		Model:  model,
		Stream: stream,
	}

	maxTokens := anthropicMaxTokensDefault
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	} else if req.MaxCompletionTokens != nil {
		maxTokens = *req.MaxCompletionTokens
	}
	out.MaxTokens = maxTokens
	out.Temperature = req.Temperature
	out.TopP = req.TopP
	out.StopSequences = req.Stop

	// system is a top-level field: every system-role message merges into it.
	var systemParts []string
	out.Messages = make([]anthMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		parts, err := splitContent(m.Content)
		if err != nil {
			return nil, err
		}
		switch m.Role {
		case "system", "developer":
			if text := joinText(parts); text != "" {
				systemParts = append(systemParts, text)
			}
			continue
		case "tool":
			// A tool result becomes a user message carrying a tool_result block.
			out.Messages = append(out.Messages, anthMessage{
				Role:    "user",
				Content: mustJSON([]anthBlock{{Type: "tool_result", ToolUseID: m.ToolCallID, Content: json.RawMessage(m.Content)}}),
			})
			continue
		}

		blocks := toAnthropicBlocks(parts, m.ToolCalls)
		out.Messages = append(out.Messages, anthMessage{
			Role:    anthropicRole(m.Role),
			Content: mustJSON(blocks),
		})
	}
	if len(systemParts) > 0 {
		out.System = mustJSON(strings.Join(systemParts, "\n\n"))
	}

	for _, t := range req.Tools {
		out.Tools = append(out.Tools, anthTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	out.ToolChoice = toAnthropicToolChoice(req.ToolChoice)

	return marshalCanonical(out)
}

// anthropicRole maps a pivot role onto an Anthropic role. Anthropic only has
// user and assistant; anything unrecognised is treated as user.
func anthropicRole(role string) string {
	if role == "assistant" {
		return "assistant"
	}
	return "user"
}

// toAnthropicBlocks converts pivot content parts and tool calls into Anthropic
// content blocks.
func toAnthropicBlocks(parts []canonicalPart, calls []canonicalTool) []anthBlock {
	blocks := make([]anthBlock, 0, len(parts)+len(calls))
	for _, p := range parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				blocks = append(blocks, anthBlock{Type: "text", Text: p.Text})
			}
		case "image_url":
			if p.ImageURL != nil && p.ImageURL.URL != "" {
				blocks = append(blocks, anthBlock{Type: "image", Source: imageSource(p.ImageURL.URL)})
			}
		}
	}
	for _, c := range calls {
		input := json.RawMessage(c.Function.Arguments)
		if len(input) == 0 {
			input = json.RawMessage("{}")
		}
		blocks = append(blocks, anthBlock{
			Type:  "tool_use",
			ID:    c.ID,
			Name:  c.Function.Name,
			Input: input,
		})
	}
	return blocks
}

// imageSource converts a pivot image URL into an Anthropic source. A data: URL
// becomes base64; a normal URL is passed as a url source (Anthropic's
// url-source support). Malformed data URLs fall back to the URL form so the
// translator never silently drops the image.
func imageSource(url string) *anthImageSource {
	if media, data, ok := splitDataURL(url); ok {
		return &anthImageSource{Type: "base64", MediaType: media, Data: data}
	}
	return &anthImageSource{Type: "url", URL: url}
}

// splitDataURL parses "data:<media>;base64,<data>". ok is false for anything
// else, so the caller chooses the URL form.
func splitDataURL(raw string) (mediaType, data string, ok bool) {
	const prefix = "data:"
	if !strings.HasPrefix(raw, prefix) {
		return "", "", false
	}
	rest := raw[len(prefix):]
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return "", "", false
	}
	meta := rest[:comma]
	payload := rest[comma+1:]
	if !strings.HasSuffix(meta, ";base64") {
		return "", "", false
	}
	return strings.TrimSuffix(meta, ";base64"), payload, true
}

// toAnthropicToolChoice maps the pivot tool_choice onto Anthropic's. Anthropic
// has {auto, any, tool}; OpenAI has {auto, none, required, {type,tool name}}.
func toAnthropicToolChoice(raw json.RawMessage) *anthToolChoice {
	if isJSONNull(raw) {
		return nil
	}
	trimmed := trimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil
		}
		switch s {
		case "auto":
			return &anthToolChoice{Type: "auto"}
		case "required":
			return &anthToolChoice{Type: "any"}
		case "none":
			// Anthropic has no explicit "none"; leaving it unset is the closest
			// behaviour (tools are advertised but not forced).
			return nil
		default:
			return nil
		}
	}
	var named struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(trimmed, &named); err == nil {
		if named.Type == "function" && named.Function.Name != "" {
			return &anthToolChoice{Type: "tool", Name: named.Function.Name}
		}
	}
	return nil
}

// --- Response: Anthropic -> pivot ---

// ResponseFull implements contracts.Translator.
func (AnthropicToOpenAI) ResponseFull(payload []byte, model string) ([]byte, error) {
	var resp anthResponse
	if err := decodeJSON(payload, &resp); err != nil {
		return nil, err
	}
	if model == "" {
		model = resp.Model
	}

	msg := canonicalMsg{Role: "assistant"}
	var textParts []canonicalPart
	var calls []canonicalTool
	for _, b := range resp.Content {
		switch b.Type {
		case "text":
			textParts = append(textParts, canonicalPart{Type: "text", Text: b.Text})
		case "tool_use":
			calls = append(calls, canonicalTool{
				ID:   b.ID,
				Type: "function",
				Function: canonicalFunction{
					Name:      b.Name,
					Arguments: compactRaw(b.Input, "{}"),
				},
			})
		}
	}
	if len(textParts) > 0 {
		msg.Content = mustJSON(joinText(textParts))
	}
	msg.ToolCalls = calls

	out := canonicalResponse{
		ID:      resp.ID,
		Object:  "chat.completion",
		Created: 0,
		Model:   model,
		Choices: []canonicalChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: anthropicFinishReason(resp.StopReason),
		}},
	}
	if resp.Usage != nil {
		out.Usage = &canonicalUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		}
	}
	return marshalCanonical(out)
}

// anthropicFinishReason maps Anthropic stop_reason onto the OpenAI
// finish_reason vocabulary.
func anthropicFinishReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "stop_sequence":
		return "stop"
	case "":
		return ""
	default:
		return reason
	}
}

// ResponseChunk implements contracts.Translator. One Anthropic SSE event is
// projected onto at most one OpenAI chat.completion.chunk. Events that carry no
// client-visible delta (ping, message_start, content_block_start of a text
// block, message_stop) return an empty byte slice, which the contract defines as
// "nothing to emit".
//
// Tool-call deltas are projected WITHOUT re-splitting: Anthropic streams the
// tool arguments as partial_json fragments and the translator forwards them as
// tool_calls[].function.arguments fragments, so the client reassembles them
// exactly as it does for OpenAI. The translator never buffers across frames.
func (AnthropicToOpenAI) ResponseChunk(payload []byte, model string) ([]byte, error) {
	var ev anthStreamEvent
	if err := decodeJSON(payload, &ev); err != nil {
		return nil, err
	}

	switch ev.Type {
	case "message_start":
		chunkModel := model
		if ev.Message != nil && ev.Message.Model != "" {
			chunkModel = ev.Message.Model
		}
		chunk := canonicalChunk{
			Object: "chat.completion.chunk",
			Model:  chunkModel,
			Choices: []canonicalChunkChoice{{
				Index: 0,
				Delta: canonicalDelta{Role: "assistant"},
			}},
		}
		return marshalCanonical(chunk)

	case "content_block_delta":
		if ev.Delta == nil {
			return nil, nil
		}
		switch ev.Delta.Type {
		case "text_delta":
			chunk := canonicalChunk{
				Object: "chat.completion.chunk",
				Model:  model,
				Choices: []canonicalChunkChoice{{
					Index: 0,
					Delta: canonicalDelta{Content: ev.Delta.Text},
				}},
			}
			return marshalCanonical(chunk)
		case "input_json_delta":
			// Forward the partial arguments; the tool call id/name was emitted
			// on content_block_start. The tool-call Index is the Anthropic
			// content-block index (ev.Index): the translator is stateless across
			// frames, so this is the only value that stays consistent between the
			// start frame and its argument fragments. Hardcoding 0 would merge
			// two parallel tool calls into one on the client (which matches
			// deltas by tool_calls[].index), losing arguments.
			chunk := canonicalChunk{
				Object: "chat.completion.chunk",
				Model:  model,
				Choices: []canonicalChunkChoice{{
					Index: 0,
					Delta: canonicalDelta{ToolCalls: []canonicalDeltaTool{{
						Index:    ev.Index,
						ID:       "",
						Type:     "function",
						Function: canonicalFunction{Arguments: ev.Delta.PartialJSON},
					}}},
				}},
			}
			return marshalCanonical(chunk)
		}
		return nil, nil

	case "content_block_start":
		if ev.ContentBlock == nil || ev.ContentBlock.Type != "tool_use" {
			return nil, nil
		}
		chunk := canonicalChunk{
			Object: "chat.completion.chunk",
			Model:  model,
			Choices: []canonicalChunkChoice{{
				Index: 0,
				Delta: canonicalDelta{ToolCalls: []canonicalDeltaTool{{
					Index: ev.Index,
					ID:    ev.ContentBlock.ID,
					Type:  "function",
					Function: canonicalFunction{
						Name: ev.ContentBlock.Name,
					},
				}}},
			}},
		}
		return marshalCanonical(chunk)

	case "message_delta":
		finish := ""
		if ev.Delta != nil {
			finish = anthropicFinishReason(ev.Delta.StopReason)
		}
		chunk := canonicalChunk{
			Object: "chat.completion.chunk",
			Model:  model,
			Choices: []canonicalChunkChoice{{
				Index:        0,
				Delta:        canonicalDelta{},
				FinishReason: finish,
			}},
		}
		if ev.Usage != nil {
			chunk.Usage = &canonicalUsage{
				PromptTokens:     ev.Usage.InputTokens,
				CompletionTokens: ev.Usage.OutputTokens,
				TotalTokens:      ev.Usage.InputTokens + ev.Usage.OutputTokens,
			}
		}
		return marshalCanonical(chunk)

	case "message_stop", "ping", "content_block_stop", "error":
		// Nothing client-visible; the transport's terminal handling covers the
		// end of stream and errors.
		return nil, nil

	default:
		// An unknown event type must not break the stream: emit nothing.
		return nil, nil
	}
}

// canonicalChunk is the pivot OpenAI streaming chunk.
type canonicalChunk struct {
	ID      string                 `json:"id,omitempty"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []canonicalChunkChoice `json:"choices"`
	Usage   *canonicalUsage        `json:"usage,omitempty"`
}

type canonicalChunkChoice struct {
	Index        int            `json:"index"`
	Delta        canonicalDelta `json:"delta"`
	FinishReason string         `json:"finish_reason,omitempty"`
}

type canonicalDelta struct {
	Role      string               `json:"role,omitempty"`
	Content   string               `json:"content,omitempty"`
	ToolCalls []canonicalDeltaTool `json:"tool_calls,omitempty"`
}

type canonicalDeltaTool struct {
	Index    int               `json:"index"`
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Function canonicalFunction `json:"function"`
}

// --- helpers ---

// mustJSON marshals v and panics on failure. It is only used with values that
// are always marshalable (structs of strings/numbers/raw JSON), so a failure is
// a programming error, not a runtime condition.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("translators: mustJSON: %v", err))
	}
	return b
}

// normalizeRaw returns raw, or fallback when raw is empty/null.
func normalizeRaw(raw json.RawMessage, fallback string) json.RawMessage {
	if isJSONNull(raw) {
		return json.RawMessage(fallback)
	}
	return raw
}
