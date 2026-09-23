package token

import (
	"bytes"
	"encoding/json"
)

// CacheablePrefixEnd is the exported form of the prefix boundary (ADR-0015 §2):
// the byte offset that separates the FROZEN cacheable prefix from the
// compressible suffix of a canonical (OpenAI-shaped) request body. It is
// exported so the composition root, the Router (session-affinity, ADR-0015 §4)
// and tests can reason about the same boundary the gate uses.
func CacheablePrefixEnd(body []byte) int { return prefixBoundary(body) }

// prefixBoundary returns the byte offset that separates the FROZEN cacheable
// prefix from the compressible suffix of a canonical (OpenAI-shaped) request
// body (ADR-0015 §2).
//
// The cacheable prefix is the initial interval a provider can reuse between
// requests of the same session: the system block(s) and the earlier conversation
// turns. The CURRENT user turn — and anything after it — is exactly what the
// provider does NOT reuse, so it is the legitimate compression target. The
// boundary is therefore the start of the LAST message whose role is "user".
//
// A body that is not a JSON object, has no "messages" array, or has no user
// message is treated as having NO stable prefix: it returns 0, meaning the whole
// prompt is suffix and may be compressed (ADR-0015 §2, "sem prefixo estável").
//
// The offset is a byte position; callers must treat every byte BEFORE it as
// immutable. It is computed from the request body only, so it is deterministic
// and free of clock/state.
func prefixBoundary(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return 0
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0
		}
		// Token() returns a string member name or an error; the type assertion
		// is defensive (a JSON object member name is always a string).
		// A JSON object member name is always a string per Token()'s contract, so
		// the assertion cannot fail; no defensive branch is needed.
		key := keyTok.(string)
		if key != "messages" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0
			}
			continue
		}
		// Consume the opening bracket of the messages array.
		if _, err := dec.Token(); err != nil {
			return 0
		}
		lastUser := 0
		for dec.More() {
			start := int(dec.InputOffset())
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return 0
			}
			if messageRole(raw) == "user" {
				lastUser = start
			}
		}
		return lastUser
	}
	return 0
}

// messageRole extracts the "role" field of one message object, or "".
func messageRole(raw []byte) string {
	var m struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	return m.Role
}
