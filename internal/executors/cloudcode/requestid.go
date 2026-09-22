package cloudcode

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// ideRequestIDShape mirrors the reference connector's regex
// `agent/<conversationId>/<ts>/<trajectoryId>/<step>`. A requestId already in
// this shape is passed through unchanged.
func looksLikeRequestID(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 5 || parts[0] != "agent" {
		return false
	}
	if parts[1] == "" || parts[3] == "" {
		return false // conversation and trajectory ids must be present
	}
	if parts[2] == "" {
		return false
	}
	if _, err := strconv.ParseInt(parts[2], 10, 64); err != nil {
		return false
	}
	if _, err := strconv.Atoi(parts[4]); err != nil {
		return false
	}
	return true
}

// buildRequestID derives a CloudCode requestId of the form
// `agent/<conversationId>/<ts>/<trajectoryId>/<step>`.
//
// UNIQUENESS + DETERMINISM: the conversation/trajectory ids are UUID-v5-style
// values derived by hashing a seed (never crypto/rand). The timestamp component
// is `now.UnixNano()` — UNIQUE per call, because CloudCode can require a
// distinct id per turn — while the conversation/trajectory/step remain a pure
// function of the request. A test injects a fixed clock (via the executor's
// `now` seam) to pin the exact string; production uses the real clock.
func buildRequestID(desc contracts.ProviderDescriptor, cred contracts.Credential, req contracts.WireRequest, sessionID string, now time.Time) string {
	conversationID := uuidFromSeed("antigravity:conversation:" + sessionID)
	trajectoryID := uuidFromSeed("antigravity:trajectory:" + sessionID + ":" + string(req.Model) + ":agent")

	// The timestamp is the wall clock (nanoseconds): unique per call, which is
	// what CloudCode needs per turn. The injected clock keeps it testable.
	ts := now.UnixNano()

	// step = max(1, contentCount*2-1); contentCount is the number of canonical
	// messages, approximated from the body's top-level "messages" array length.
	steps := max(1, contentCount(req.Body)*2-1)

	return "agent/" + conversationID + "/" + strconv.FormatInt(ts, 10) + "/" + trajectoryID + "/" + strconv.Itoa(steps)
}

// contentCount returns the number of top-level messages in a canonical request
// body, or 1 when it cannot be read.
func contentCount(body []byte) int {
	obj := decodeObject(body)
	if obj == nil {
		return 1
	}
	raw, ok := obj["messages"]
	if !ok {
		return 1
	}
	var msgs []jsonRaw
	if err := jsonUnmarshal(raw, &msgs); err != nil {
		return 1
	}
	if len(msgs) == 0 {
		return 1
	}
	return len(msgs)
}

// uuidFromSeed derives a UUID-v5-shaped value from a seed by hashing. It is the
// deterministic analogue of the reference connector's uuidFromSeed.
func uuidFromSeed(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	// Version 5 (name-based) and RFC 4122 variant.
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
