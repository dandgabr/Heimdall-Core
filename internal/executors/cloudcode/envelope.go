package cloudcode

import (
	"encoding/json"
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// envelope is the CloudCode request wrapper:
//
//	{project, model, userAgent, requestId, request:{contents, tools,
//	 generationConfig, sessionId, ...}}
//
// toolMap is the reverse tool-cloaking map the executor keeps to uncloak response
// tool names; it NEVER crosses the wire (set in buildEnvelope, not marshalled).
type envelope struct {
	Project   string
	Model     string
	UserAgent string
	RequestID string
	SessionID string
	Request   json.RawMessage

	toolMap map[string]string
}

// wireEnvelope is the exact JSON shape sent upstream. The toolMap and the
// derived SessionID are deliberately absent.
type wireEnvelope struct {
	Project   string          `json:"project"`
	Model     string          `json:"model"`
	UserAgent string          `json:"userAgent"`
	RequestID string          `json:"requestId"`
	Request   json.RawMessage `json:"request"`
}

// marshal encodes the envelope for the wire.
func (e envelope) marshal() ([]byte, error) {
	return jsonMarshal(wireEnvelope{
		Project:   e.Project,
		Model:     e.Model,
		UserAgent: e.UserAgent,
		RequestID: e.RequestID,
		Request:   e.Request,
	})
}

// blacklistedFields are the Google-rejected fields that Claude/OpenAI/Qwen
// thinking extensions set on the request; the provider rejects a request that
// carries them, so they are stripped before the CloudCode call.
var blacklistedFields = []string{
	"output_config",
	"thinking",
	"reasoning_effort",
	"reasoning",
	"enable_thinking",
	"thinking_budget",
	"thinkingConfig",
}

// cleanRequest takes the Gemini request body, strips the blacklisted fields, and
// drops stream_options when the call is not streaming. It also injects the
// sessionId, which the CloudCode envelope requires inside the request object.
func cleanRequest(gemini []byte, stream bool, sessionID string) (json.RawMessage, error) {
	obj := decodeObject(gemini)
	if obj == nil {
		// Not an object: wrap the bytes as-is plus a sessionId object.
		wrapped := map[string]json.RawMessage{"sessionId": jsonString(sessionID)}
		_ = wrapped
		out := make(json.RawMessage, len(gemini))
		copy(out, gemini)
		return out, nil
	}
	for _, k := range blacklistedFields {
		delete(obj, k)
	}
	if !stream {
		delete(obj, "stream_options")
	}
	obj["sessionId"] = jsonString(sessionID)
	capMaxOutputTokens(obj)
	out, err := jsonMarshal(obj)
	if err != nil {
		return nil, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
		)
	}
	return out, nil
}

// capMaxOutputTokens clamps generationConfig.maxOutputTokens to the Antigravity
// cap (64000). It mutates obj in place (the caller re-marshals it), so the cap
// actually reaches the wire; it is a no-op when the field is absent or already
// within the cap.
func capMaxOutputTokens(obj map[string]json.RawMessage) {
	genRaw, ok := obj["generationConfig"]
	if !ok {
		return
	}
	gen := decodeObject(genRaw)
	if gen == nil {
		return
	}
	n, ok := numToInt(gen["maxOutputTokens"])
	if !ok || n <= maxOutputTokensCap {
		return
	}
	gen["maxOutputTokens"] = json.RawMessage(strconv.Itoa(maxOutputTokensCap))
	if reencoded, err := jsonMarshal(gen); err == nil {
		obj["generationConfig"] = reencoded
	}
}

// decodeObject unmarshals raw into a generic object, returning nil for anything
// that is not a JSON object.
func decodeObject(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}

// numToInt decodes a JSON number.
func numToInt(raw json.RawMessage) (int, bool) {
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	return n, true
}

// jsonString marshals a Go string into a JSON raw string value.
func jsonString(s string) json.RawMessage {
	b, _ := jsonMarshal(s)
	return b
}

// unwrapResponse extracts the Gemini payload from the CloudCode wrapper. The
// CloudCode response is {"response": {...}}; when there is no "response" key the
// payload is returned as-is (some error frames carry the error shape directly).
func unwrapResponse(body []byte) []byte {
	obj := decodeObject(body)
	if obj == nil {
		return body
	}
	if inner, ok := obj["response"]; ok && len(inner) > 0 {
		return inner
	}
	return body
}
