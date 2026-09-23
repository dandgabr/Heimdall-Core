package gateway

import (
	"net/http"
	"strings"
)

// This file resolves the G-1 finding of the F4 validation: the stateful gates
// (the rate limiter, the memory gates) key their state on a client identity
// that no HTTP boundary provided. The gateway is the boundary that talks to
// the client, so it is the one that extracts the identity the request ALREADY
// presents and hands it to the gates through GateInput.Meta.
//
// Honesty about what this is NOT: with client authentication landing in F5
// (BD-01/P1-6), the extracted key is a CLIENT-DECLARED identity, unverified.
// It is good enough for best-effort separation of throttle buckets and memory
// namespaces; it is NOT an authentication decision, and a client can present
// different keys per request (each key simply gets its own bucket/namespace).
// The F5 contract will replace this with an authenticated key.
//
// Privacy: the key lives only in the request-scoped Meta map. The stateful
// gates derive a SHA-256 namespace (memory) or an in-memory map index
// (throttle) from it; no gate logs it, the logger gate sees header NAMES only,
// and the central redactor guards every diagnostic surface.

// ClientKeyMeta is the GateInput.Meta key the stateful gates read. It mirrors
// the security and memory families' reserved boundary key (security.MetaKeyClient
// / memory.MetaKeyClient); the gateway cannot import the gate packages (it is
// consumed THROUGH them via the Chain port), so the literal is pinned here and
// by the parity the propagation tests prove.
const ClientKeyMeta = "client.key"

// ClientKeyFromHeaders extracts the client identity a request presents,
// preferring the OpenAI-compatible form (Authorization: Bearer <key>) and
// falling back to the Anthropic-style dedicated header (X-API-Key).
//
// Absence rules: no identity headers at all, a non-Bearer Authorization
// scheme, or a Bearer header with an empty token all yield "" — the caller
// leaves the Meta key ABSENT rather than inventing a value. A present-but-
// malformed Authorization deliberately does NOT fall through to X-API-Key:
// the client declared an identity form and failed to provide it, which the
// gates treat exactly like absence.
func ClientKeyFromHeaders(h http.Header) string {
	if auth := strings.TrimSpace(h.Get("Authorization")); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			if token = strings.TrimSpace(token); token != "" {
				return token
			}
		}
		return "" // declared an Authorization that carries no usable key
	}
	if key := strings.TrimSpace(h.Get("X-API-Key")); key != "" {
		return key
	}
	return ""
}
