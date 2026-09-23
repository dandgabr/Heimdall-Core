package gateway

import (
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/observability"
)

// This file resolves the G-1 finding of the F4 validation and lands the F5
// client-identity contract (ADR-SEC-06 §2).
//
// In F4 the gateway extracted a CLIENT-DECLARED identity straight from the
// request headers. That was honest best-effort separation of throttle buckets
// and memory namespaces, but it was NOT authentication: a client could present
// any string, and a management token was as good as a key.
//
// F5 makes the CANONICAL source the AUTHENTICATED client key: the client-key
// middleware (internal/api/middleware) verifies the presented key (hash,
// constant-time, revoked-aware) and injects a NON-SECRET domain.ClientID into
// the request context. The gateway reads that identity — never the raw header —
// and hands it to the stateful gates through GateInput.Meta. A request with no
// authenticated identity leaves the Meta key ABSENT (the documented shared
// bucket / inert memory namespace); the gateway never invents one and never
// falls back to an unverified header.

// ClientKeyMeta is the GateInput.Meta key the stateful gates read. It mirrors
// the security and memory families' reserved boundary key (security.MetaKeyClient
// / memory.MetaKeyClient); the gateway cannot import the gate packages (it is
// consumed THROUGH them via the Chain port), so the literal is pinned here and
// by the parity the propagation tests prove.
const ClientKeyMeta = "client.key"

// ClientKeyFromContext returns the AUTHENTICATED client identity the client-key
// middleware injected after verifying the presented key, or "" when the request
// carried none. The value is a non-secret ClientID; the plaintext key never
// reaches this layer.
func ClientKeyFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	return observability.ClientIDFrom(r.Context())
}
