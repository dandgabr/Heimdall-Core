package contracts

import "bytes"

// This file holds the SSE terminador shared by every decoder, so the two
// executors (OpenAI-compatible and CloudCode) cannot diverge on how the OpenAI
// `[DONE]` sentinel is treated.
//
// The sentinel is NOT a chunk: it is the end of the stream. A decoder that
// delivered it as a Chunk would hand `[DONE]` to the gateway, which then emits
// its own terminal `data: [DONE]` — producing TWO sentinels and breaking strict
// SSE clients (F3 validation D-01). The check lives here, at the contract level,
// so the invariant holds for ANY consumer of a Stream, not only the gateway.

// SSEDone is the OpenAI stream terminator payload.
var SSEDone = []byte("[DONE]")

// IsSSEDone reports whether an SSE `data:` payload is the OpenAI `[DONE]`
// sentinel. It trims surrounding whitespace because the sentinel is commonly
// written `data: [DONE]` (one leading space) and a decoder must not miss it on a
// formatting difference.
func IsSSEDone(data []byte) bool {
	return bytes.Equal(bytes.TrimSpace(data), SSEDone)
}
