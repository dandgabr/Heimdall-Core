package translators

import (
	"encoding/json"
	"strings"
)

// stringOrSlice decodes an OpenAI field that accepts either a single string or
// an array of strings ("stop" is the canonical example). It preserves which form
// was used so a round-trip through a cross-format translator can choose the
// provider's representation (Anthropic/Gemini both want an array).
type stringOrSlice []string

// UnmarshalJSON accepts a JSON string or array of strings.
func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	trimmed := trimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*s = nil
		return nil
	}
	if trimmed[0] == '"' {
		var one string
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return err
		}
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(trimmed, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// MarshalJSON always emits an array. A provider that wants a scalar string
// renders it from the slice; keeping the canonical side an array is lossless
// and deterministic.
func (s stringOrSlice) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	return json.Marshal([]string(s))
}

// splitContent decodes an OpenAI message content field, which may be:
//   - absent / null        -> nil parts
//   - a JSON string        -> one text part
//   - an array of parts    -> the decoded parts
//
// It is the pivot's single decoding point for content, so every cross-format
// translator sees the same normalised form.
func splitContent(raw json.RawMessage) ([]canonicalPart, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	trimmed := trimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, failed("invalid message content string", err)
		}
		return []canonicalPart{{Type: "text", Text: text}}, nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var parts []canonicalPart
		if err := json.Unmarshal(trimmed, &parts); err != nil {
			return nil, failed("invalid message content array", err)
		}
		return parts, nil
	}
	return nil, failed("message content must be a string or an array", nil)
}

// joinText concatenates the text parts of a message. Providers that place the
// system prompt in a single top-level field (Anthropic, Gemini) need this.
func joinText(parts []canonicalPart) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// marshalCanonical serialises a value to compact JSON. It is the single encoder
// the translators use, so the golden output is always compact and stable.
func marshalCanonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

// decodeJSON unmarshals a provider payload into out, wrapping a syntax error as
// translate.failed. A malformed upstream payload is not a client error, but the
// translator cannot classify transport scope (ADR-0002 assigns ScopeProvider to
// upstream shape problems); it returns ScopeProvider via providerShapeError.
func decodeJSON(payload []byte, out any) error {
	if len(payload) == 0 {
		return providerShapeError("empty provider payload", nil)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return providerShapeError("malformed provider payload", err)
	}
	return nil
}
