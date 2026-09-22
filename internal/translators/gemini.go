package translators

import (
	"encoding/json"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// GeminiToOpenAI translates between the canonical OpenAI pivot and the Gemini
// generateContent API. From is the pivot, To is Gemini.
//
// Gemini shape differences the translator handles:
//   - the system prompt is a top-level systemInstruction with parts;
//   - the conversation is contents[] with role "user"/"model" (no "assistant");
//   - generation parameters live under generationConfig (temperature,
//     maxOutputTokens, stopSequences), not top-level;
//   - tools are functionDeclarations and calls/results are functionCall /
//     functionResponse parts;
//   - streaming frames are candidates[].content.parts[].text deltas.
type GeminiToOpenAI struct{}

var _ contracts.Translator = GeminiToOpenAI{}

// From implements contracts.Translator.
func (GeminiToOpenAI) From() contracts.WireFormat { return contracts.WireOpenAI }

// To implements contracts.Translator.
func (GeminiToOpenAI) To() contracts.WireFormat { return contracts.WireGemini }

// --- Gemini wire types ---

type gemRequest struct {
	Contents          []gemContent      `json:"contents"`
	SystemInstruction *gemContent       `json:"systemInstruction,omitempty"`
	GenerationConfig  *gemGenerationCfg `json:"generationConfig,omitempty"`
	Tools             []gemTool         `json:"tools,omitempty"`
	ToolConfig        *gemToolConfig    `json:"toolConfig,omitempty"`
}

type gemContent struct {
	Role  string    `json:"role,omitempty"`
	Parts []gemPart `json:"parts"`
}

type gemPart struct {
	Text             string           `json:"text,omitempty"`
	InlineData       *gemInlineData   `json:"inlineData,omitempty"`
	FileData         *gemFileData     `json:"fileData,omitempty"`
	FunctionCall     *gemFunctionCall `json:"functionCall,omitempty"`
	FunctionResponse *gemFunctionResp `json:"functionResponse,omitempty"`
}

type gemInlineData struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

type gemFileData struct {
	MimeType string `json:"mimeType,omitempty"`
	FileURI  string `json:"fileUri"`
}

type gemFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type gemFunctionResp struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type gemGenerationCfg struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type gemTool struct {
	FunctionDeclarations []gemFunctionDecl `json:"functionDeclarations"`
}

type gemFunctionDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type gemToolConfig struct {
	FunctionCallingConfig *gemFunctionCallingConfig `json:"functionCallingConfig,omitempty"`
}

type gemFunctionCallingConfig struct {
	Mode                 string   `json:"mode,omitempty"`
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

// gemResponse is a non-streaming generateContent response.
type gemResponse struct {
	Candidates    []gemCandidate    `json:"candidates"`
	UsageMetadata *gemUsageMetadata `json:"usageMetadata,omitempty"`
	ModelVersion  string            `json:"modelVersion,omitempty"`
}

type gemCandidate struct {
	Content      gemContent `json:"content"`
	FinishReason string     `json:"finishReason,omitempty"`
}

type gemUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// --- Request: pivot -> Gemini ---

// Request implements contracts.Translator.
func (GeminiToOpenAI) Request(canonical []byte, model string, stream bool) ([]byte, error) {
	var req canonicalRequest
	if err := decodeJSON(canonical, &req); err != nil {
		return nil, err
	}

	out := gemRequest{}
	var systemParts []string

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
			out.Contents = append(out.Contents, gemContent{
				Role: "user",
				Parts: []gemPart{{FunctionResponse: &gemFunctionResp{
					Name:     m.ToolCallID,
					Response: json.RawMessage(normalizeRaw(m.Content, "{}")),
				}}},
			})
			continue
		}

		out.Contents = append(out.Contents, gemContent{
			Role:  geminiRole(m.Role),
			Parts: toGeminiParts(parts, m.ToolCalls),
		})
	}
	if len(systemParts) > 0 {
		out.SystemInstruction = &gemContent{
			Parts: []gemPart{{Text: strings.Join(systemParts, "\n\n")}},
		}
	}

	out.GenerationConfig = buildGeminiGenerationConfig(&req)
	if len(req.Tools) > 0 {
		decls := make([]gemFunctionDecl, 0, len(req.Tools))
		for _, t := range req.Tools {
			decls = append(decls, gemFunctionDecl{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			})
		}
		out.Tools = []gemTool{{FunctionDeclarations: decls}}
	}
	out.ToolConfig = toGeminiToolConfig(req.ToolChoice)

	return marshalCanonical(out)
}

// geminiRole maps a pivot role onto a Gemini role ("assistant" -> "model").
func geminiRole(role string) string {
	if role == "assistant" {
		return "model"
	}
	return "user"
}

// toGeminiParts converts pivot content parts and tool calls into Gemini parts.
func toGeminiParts(parts []canonicalPart, calls []canonicalTool) []gemPart {
	out := make([]gemPart, 0, len(parts)+len(calls))
	for _, p := range parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				out = append(out, gemPart{Text: p.Text})
			}
		case "image_url":
			if p.ImageURL != nil && p.ImageURL.URL != "" {
				if media, data, ok := splitDataURL(p.ImageURL.URL); ok {
					out = append(out, gemPart{InlineData: &gemInlineData{MimeType: media, Data: data}})
				} else {
					out = append(out, gemPart{FileData: &gemFileData{FileURI: p.ImageURL.URL}})
				}
			}
		}
	}
	for _, c := range calls {
		out = append(out, gemPart{FunctionCall: &gemFunctionCall{
			Name: c.Function.Name,
			Args: json.RawMessage(normalizeRaw(json.RawMessage(c.Function.Arguments), "{}")),
		}})
	}
	return out
}

// buildGeminiGenerationConfig assembles generationConfig only from fields that
// were actually set, so an absent field is not sent as a zero.
func buildGeminiGenerationConfig(req *canonicalRequest) *gemGenerationCfg {
	cfg := &gemGenerationCfg{
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.Stop,
	}
	if req.MaxTokens != nil {
		cfg.MaxOutputTokens = req.MaxTokens
	} else if req.MaxCompletionTokens != nil {
		cfg.MaxOutputTokens = req.MaxCompletionTokens
	}
	if cfg.Temperature == nil && cfg.TopP == nil && cfg.MaxOutputTokens == nil && len(cfg.StopSequences) == 0 {
		return nil
	}
	return cfg
}

// toGeminiToolConfig maps the pivot tool_choice onto Gemini's
// functionCallingConfig. Gemini modes are AUTO, ANY, NONE.
func toGeminiToolConfig(raw json.RawMessage) *gemToolConfig {
	if isJSONNull(raw) {
		return nil
	}
	trimmed := trimSpace(raw)
	mode := ""
	var allowed []string
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil
		}
		switch s {
		case "none":
			mode = "NONE"
		case "required":
			mode = "ANY"
		case "auto":
			mode = "AUTO"
		}
	} else {
		var named struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		}
		if err := json.Unmarshal(trimmed, &named); err == nil && named.Type == "function" && named.Function.Name != "" {
			mode = "ANY"
			allowed = []string{named.Function.Name}
		}
	}
	if mode == "" {
		return nil
	}
	return &gemToolConfig{FunctionCallingConfig: &gemFunctionCallingConfig{
		Mode:                 mode,
		AllowedFunctionNames: allowed,
	}}
}

// --- Response: Gemini -> pivot ---

// ResponseFull implements contracts.Translator.
func (GeminiToOpenAI) ResponseFull(payload []byte, model string) ([]byte, error) {
	var resp gemResponse
	if err := decodeJSON(payload, &resp); err != nil {
		return nil, err
	}
	if model == "" {
		model = resp.ModelVersion
	}

	msg := canonicalMsg{Role: "assistant"}
	finish := ""
	if len(resp.Candidates) > 0 {
		cand := resp.Candidates[0]
		finish = geminiFinishReason(cand.FinishReason)
		var textParts []canonicalPart
		var calls []canonicalTool
		for _, p := range cand.Content.Parts {
			switch {
			case p.Text != "":
				textParts = append(textParts, canonicalPart{Type: "text", Text: p.Text})
			case p.FunctionCall != nil:
				calls = append(calls, canonicalTool{
					Type: "function",
					Function: canonicalFunction{
						Name:      p.FunctionCall.Name,
						Arguments: compactRaw(p.FunctionCall.Args, "{}"),
					},
				})
			}
		}
		if len(textParts) > 0 {
			msg.Content = mustJSON(joinText(textParts))
		}
		msg.ToolCalls = calls
	}

	out := canonicalResponse{
		Object:  "chat.completion",
		Created: 0,
		Model:   model,
		Choices: []canonicalChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: finish,
		}},
	}
	if resp.UsageMetadata != nil {
		out.Usage = &canonicalUsage{
			PromptTokens:     resp.UsageMetadata.PromptTokenCount,
			CompletionTokens: resp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      resp.UsageMetadata.TotalTokenCount,
		}
	}
	return marshalCanonical(out)
}

// geminiFinishReason maps Gemini finishReason onto the OpenAI vocabulary.
func geminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII":
		return "content_filter"
	case "":
		return ""
	default:
		return reason
	}
}

// ResponseChunk implements contracts.Translator. One Gemini streaming frame is
// projected onto at most one OpenAI chunk. Text parts become content deltas,
// functionCall parts become tool_calls deltas, and the frame's usageMetadata
// (present on the final frame) becomes the chunk usage.
func (GeminiToOpenAI) ResponseChunk(payload []byte, model string) ([]byte, error) {
	var frame gemResponse
	if err := decodeJSON(payload, &frame); err != nil {
		return nil, err
	}

	delta := canonicalDelta{}
	finish := ""
	if len(frame.Candidates) > 0 {
		cand := frame.Candidates[0]
		finish = geminiFinishReason(cand.FinishReason)
		var text strings.Builder
		var calls []canonicalDeltaTool
		for _, p := range cand.Content.Parts {
			switch {
			case p.Text != "":
				text.WriteString(p.Text)
			case p.FunctionCall != nil:
				calls = append(calls, canonicalDeltaTool{
					Index: len(calls),
					Type:  "function",
					Function: canonicalFunction{
						Name:      p.FunctionCall.Name,
						Arguments: compactRaw(p.FunctionCall.Args, "{}"),
					},
				})
			}
		}
		delta.Content = text.String()
		delta.ToolCalls = calls
	}

	// A frame with no content and no terminal reason and no usage is noise;
	// emit nothing rather than an empty chunk.
	if delta.Content == "" && len(delta.ToolCalls) == 0 && finish == "" && frame.UsageMetadata == nil {
		return nil, nil
	}

	chunk := canonicalChunk{
		Object: "chat.completion.chunk",
		Model:  model,
		Choices: []canonicalChunkChoice{{
			Index:        0,
			Delta:        delta,
			FinishReason: finish,
		}},
	}
	if frame.UsageMetadata != nil {
		chunk.Usage = &canonicalUsage{
			PromptTokens:     frame.UsageMetadata.PromptTokenCount,
			CompletionTokens: frame.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      frame.UsageMetadata.TotalTokenCount,
		}
	}
	return marshalCanonical(chunk)
}
