// Package obfuscate is the per-provider harness-fingerprint layer (ADR-0003).
//
// It is a PURE, DETERMINISTIC leaf package: no context, no network, no clock, no
// os, no randomness. The same descriptor + input bytes MUST produce the same
// output bytes on every run and machine, which is what makes the golden files
// meaningful and what lets a connector be tested without a network. The only
// imports are internal/contracts, internal/domain and the standard library.
//
// # Scope
//
// The layer has four independent techniques, applied by the family's executor,
// never globally (ADR-0003 §1):
//
//   - Apply rewrites the system prompt (PromptRewrite, literal or regex).
//   - CloakTools renames client tools with NameSuffix and injects DecoyTools.
//   - UncloakToolName reverses a cloaked tool name in a response.
//   - UserAgent and SyntheticProject produce the fingerprint identity values.
//
// # Invariants
//
//  1. IDENTITY WHEN EMPTY. A descriptor with no obfuscation (see
//     ProviderDescriptor.IsObfuscated) makes Apply and CloakTools return the
//     input unchanged. Obfuscation is never applied "just in case".
//  2. REVERSIBLE TOOL NAMES. CloakTools returns the map suffixed->original, so a
//     response can be uncloaked; UncloakToolName is the inverse and is total
//     (an unknown name is returned unchanged, never dropped).
//  3. NO RANDOMNESS. SyntheticProject derives from a seed by hashing, never
//     crypto/rand directly: the value is stable for a seed and the caller
//     controls the seed, so it is reproducible and testable.
//  4. NEVER USER IDENTITY. The obfuscation is of the harness/client, never of
//     who the user is (ADR-0003 §5). Nothing here touches credential or account
//     data.
//  5. PROTOCOL-AGNOSTIC. The package rewrites a canonical OpenAI-shaped body; it
//     knows nothing about the CloudCode/Gemini/Anthropic envelope.
package obfuscate

import (
	"encoding/json"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// Apply rewrites the system prompt of a canonical OpenAI-shaped request body
// according to desc.Obfuscation.PromptRewrites, in order. Literal rewrites
// replace every occurrence; regex rewrites use RE2 semantics. The body is
// re-encoded compactly and the original fields are preserved except for the
// rewritten system text.
//
// If the descriptor declares no prompt rewrites, Apply returns the input bytes
// unchanged (identity), allocated as a defensive copy so the caller cannot alias
// this package's memory.
func Apply(desc contracts.ProviderDescriptor, canonical []byte) ([]byte, error) {
	if len(desc.Obfuscation.PromptRewrites) == 0 {
		return copyBytes(canonical), nil
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &body); err != nil {
		return nil, obfuscationError("invalid request body", err)
	}

	// The system text lives in the "messages" array: a message with role
	// "system" (or "developer"). Its content is either a plain string or an
	// array of {"type":"text","text":...} parts. The rewrite applies to the
	// concatenation of that text and is written back into the same shape.
	rawMessages, ok := body["messages"]
	if ok {
		rewritten, changed, err := rewriteMessages(rawMessages, desc.Obfuscation.PromptRewrites)
		if err != nil {
			return nil, err
		}
		if changed {
			body["messages"] = rewritten
		}
	}

	out, err := marshalJSON(body)
	if err != nil {
		return nil, obfuscationError("could not re-encode request body", err)
	}
	return out, nil
}

// rewriteMessages walks the messages array and applies the rewrites to every
// system/developer message. It reports whether anything changed so Apply can
// leave the input untouched otherwise.
func rewriteMessages(raw json.RawMessage, rules []contracts.PromptRewrite) (json.RawMessage, bool, error) {
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &messages); err != nil {
		return nil, false, obfuscationError("invalid messages array", err)
	}

	changed := false
	for _, msg := range messages {
		var role string
		if r, ok := msg["role"]; ok {
			_ = json.Unmarshal(r, &role)
		}
		if role != "system" && role != "developer" {
			continue
		}
		content, ok := msg["content"]
		if !ok {
			continue
		}
		newContent, didChange, err := rewriteContent(content, rules)
		if err != nil {
			return nil, false, err
		}
		if didChange {
			msg["content"] = newContent
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}

	out, err := marshalJSON(messages)
	if err != nil {
		return nil, false, obfuscationError("could not re-encode messages", err)
	}
	return out, true, nil
}

// rewriteContent rewrites either a string content or a content-parts array. It
// uses shape DETECTION rather than validation-returning-error: a value that is
// neither a string nor a parts array is passed through untouched, because a
// content RawMessage extracted from an already-parsed body is always valid JSON,
// so an "invalid JSON" error branch here would be unreachable. A shape this
// package does not model is left alone, never guessed at.
func rewriteContent(raw json.RawMessage, rules []contracts.PromptRewrite) (json.RawMessage, bool, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return raw, false, nil
	}

	// Shape 1: a plain string.
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err == nil {
			rewritten, changed, err := rewriteText(text, rules)
			if err != nil {
				return nil, false, err
			}
			if !changed {
				return raw, false, nil
			}
			out, err := marshalJSON(rewritten)
			if err != nil {
				return nil, false, obfuscationError("could not re-encode system content", err)
			}
			return out, true, nil
		}
	}

	// Shape 2: an array of content parts.
	if trimmed[0] == '[' {
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &parts); err == nil {
			changed := false
			for _, part := range parts {
				var ptype string
				if t, ok := part["type"]; ok {
					_ = json.Unmarshal(t, &ptype)
				}
				if ptype != "text" {
					continue
				}
				textRaw, ok := part["text"]
				if !ok {
					continue
				}
				var text string
				if err := json.Unmarshal(textRaw, &text); err != nil {
					continue
				}
				rewritten, didChange, err := rewriteText(text, rules)
				if err != nil {
					return nil, false, err
				}
				if didChange {
					part["text"], _ = marshalJSON(rewritten)
					changed = true
				}
			}
			if !changed {
				return raw, false, nil
			}
			out, err := marshalJSON(parts)
			if err != nil {
				return nil, false, obfuscationError("could not re-encode system content parts", err)
			}
			return out, true, nil
		}
	}

	// Unknown shape: leave it untouched rather than guess.
	return raw, false, nil
}
