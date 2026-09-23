package middleware

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/observability"
)

// This file holds the F5.1 HTTP trust guards (ADR-SEC-06 §3): the Host guard
// against DNS rebinding, the Origin/Referer guard against CSRF on the
// management/GUI surfaces, the closed-by-default CORS policy and the
// client-key authentication of the inference gateway.
//
// Coverage discipline: HostGuard wraps the WHOLE mux (catch-all), so a route
// registered later is protected by construction — the same rule LocalOnly
// follows. OriginGuard, CORS and ClientAuth are catch-all too, but each decides
// internally which ROUTE CLASS it governs (management/GUI vs inference), which
// is what keeps the two credential domains apart: a management token is never
// accepted on /v1/* and a client key never on /api/mgmt/*.

// HostGuard rejects a request whose Host header is not a local name
// (ADR-SEC-06 §3.1). Loopback forms are always accepted; extra names come from
// the operator allowlist (an allow-remote deployment). A public name or a
// rebinding domain such as "127.0.0.1.nip.io" is rejected with 403 BEFORE any
// authentication, because the peer IP being loopback is exactly the condition
// DNS rebinding produces.
func HostGuard(allowlist []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HostAllowed(r.Host, allowlist) {
				WriteError(w, r, domain.New(domain.CodeServerHostInvalid,
					domain.WithHTTPStatus(http.StatusForbidden)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HostAllowed reports whether a Host header value is accepted: a loopback form
// (with or without port) or an explicit allowlist entry (compared case-
// insensitively, with or without port). An empty Host is rejected (fail-closed).
func HostAllowed(host string, allowlist []string) bool {
	h := hostWithoutPort(host)
	if h == "" {
		return false
	}
	if isLoopbackHostName(h) {
		return true
	}
	for _, allowed := range allowlist {
		if strings.EqualFold(hostWithoutPort(allowed), h) {
			return true
		}
	}
	return false
}

// isLoopbackHostName reports whether a host (no port, no brackets) is a
// loopback form: "localhost" or a loopback IP literal. It never resolves a
// name, so a domain that merely points at 127.0.0.1 is not accepted.
func isLoopbackHostName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// hostWithoutPort strips the port from a Host value and the brackets from an
// IPv6 literal. "[::1]:8787" -> "::1", "127.0.0.1:8787" -> "127.0.0.1",
// "localhost" -> "localhost".
func hostWithoutPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := splitHostPort(raw); err == nil {
		return host
	}
	// No port: strip IPv6 brackets if present.
	return strings.Trim(raw, "[]")
}

// splitHostPort is net.SplitHostPort with IPv6 brackets normalised away from
// the returned host, so callers always get a bare address.
func splitHostPort(raw string) (string, string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", err
	}
	return strings.Trim(host, "[]"), port, nil
}

// OriginGuard rejects a MUTATING request to the management API or the GUI whose
// Origin/Referer is not a local origin (ADR-SEC-06 §3.2, anti-CSRF). A request
// with neither header (a CLI/script) is allowed: the header cannot be forged by
// a browser, so its absence is not a browser-driven cross-site request.
func OriginGuard(extra []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isManagementOrGUI(r.URL.Path) || !isMutating(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if !originAllowed(r, extra) {
				WriteError(w, r, domain.New(domain.CodeServerOriginInvalid,
					domain.WithHTTPStatus(http.StatusForbidden)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed validates the Origin (preferred) or Referer of a mutating
// management request against the local origins. Both absent is allowed;
// anything present must resolve to a loopback origin (any port — the browser
// owns the header, so a cross-site attacker cannot present a loopback origin)
// or an exact operator-configured origin.
func originAllowed(r *http.Request, extra []string) bool {
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		raw = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if isLoopbackHostName(u.Hostname()) {
		return true
	}
	for _, allowed := range extra {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), u.Scheme+"://"+u.Host) {
			return true
		}
	}
	return false
}

// isManagementOrGUI reports whether a path belongs to the management API or the
// GUI asset surface, the two origin-checked route classes.
func isManagementOrGUI(path string) bool {
	return strings.HasPrefix(path, "/api/mgmt/") || strings.HasPrefix(path, "/web/") || path == "/web"
}

// isMutating reports whether a method changes state and therefore needs the
// anti-CSRF origin check.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// CORS applies a CLOSED cross-origin policy to the inference gateway
// (ADR-SEC-06 §3.3): an origin is echoed back only when it is on the explicit
// allowlist, a wildcard is never emitted, and the management surface is never
// made cross-origin permissive. Preflight (OPTIONS) is answered only for an
// allowed origin; otherwise it is refused.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !corsAllowed(origin, allowedOrigins) {
				// Not on the allowlist: no CORS headers, and a preflight is
				// refused outright. A simple request proceeds and the browser
				// blocks the response (the correct closed behaviour).
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin) // echo, never "*"
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// corsAllowed reports whether an origin is on the closed allowlist. The
// comparison is exact (scheme://host[:port]); "*" is never accepted.
func corsAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" {
			continue
		}
		if strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

// ClientKeyVerifier authenticates a presented client key and returns the
// matching non-secret client identity.
type ClientKeyVerifier func(ctx context.Context, presented string) (domain.ClientID, bool)

// ClientAuth authenticates the inference gateway (/v1/*) with a CLIENT KEY,
// never the management token (ADR-SEC-06 §2). It is applied to every mutating
// /v1/* route (read-only /v1/models stays public), and it is scoped to the path
// so a management request's token is never interpreted as a client key.
//
// Behaviour:
//   - a key in the URL query string is refused with 400 error.invalid_request
//     (it would leak into access logs);
//   - an ABSENT key is admitted only when require is false (the local
//     out-of-the-box default); the request then carries no client identity and
//     the stateful gates use their documented shared bucket;
//   - a PRESENT key that does not verify (unknown, revoked or the management
//     token) is always rejected with 401 clientkey.invalid;
//   - a verified key injects the non-secret ClientID into the request context.
func ClientAuth(verify ClientKeyVerifier, require bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			// A key in the query string is forbidden on EVERY /v1/* path,
			// including the read-only ones: the URL is the surface that leaks
			// into access logs, browser history and proxies (ADR-SEC-06 §2.2,
			// §7.4: HTTP 400 error.invalid_request).
			if keyInQuery(r.URL.Query()) {
				WriteError(w, r, domain.New(domain.CodeInvalidRequest,
					domain.WithHTTPStatus(http.StatusBadRequest),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{
						"reason": "client keys must not be passed in the URL query string; use the Authorization header",
					})))
				return
			}
			// Read-only /v1/models is public (ADR-SEC-06 §1 route classes); only
			// a stateful inference call requires a client key.
			if !isMutating(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			key := ExtractClientKey(r.Header)
			if key == "" {
				if require {
					writeClientKeyInvalid(w, r)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			id, ok := verify(r.Context(), key)
			if !ok {
				writeClientKeyInvalid(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(observability.WithClientID(r.Context(), id)))
		})
	}
}

// keyInQuery reports whether a client key was smuggled into the URL query
// string — forbidden outright (ADR-SEC-06 §2.2). Both the OpenAI-style
// api_key and the generic token parameter names are covered.
func keyInQuery(q url.Values) bool {
	for _, name := range []string{"api_key", "apikey", "token", "key", "access_token"} {
		if strings.TrimSpace(q.Get(name)) != "" {
			return true
		}
	}
	return false
}

// ExtractClientKey reads the presented client key from the two accepted
// transport headers, OpenAI-style first (Authorization: Bearer) then
// Anthropic-style (x-api-key). A malformed Authorization (non-Bearer scheme, or
// a Bearer with no token) counts as ABSENT — the client declared an identity
// form and failed to supply it.
func ExtractClientKey(h http.Header) string {
	if auth := strings.TrimSpace(h.Get("Authorization")); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(token)
		}
		return ""
	}
	return strings.TrimSpace(h.Get("X-API-Key"))
}

// ClientIDFrom returns the AUTHENTICATED client identity the ClientAuth guard
// injected, or "" when the request carried no authenticated key. It is a thin
// wrapper over the observability accessor so the middleware package owns the
// name its guards use.
func ClientIDFrom(r *http.Request) string {
	if r == nil {
		return ""
	}
	return observability.ClientIDFrom(r.Context())
}

// writeClientKeyInvalid emits the 401 clientkey.invalid envelope. The message
// never says whether the key existed: an unknown and a revoked key are
// indistinguishable to the caller.
func writeClientKeyInvalid(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, domain.New(domain.CodeClientKeyInvalid,
		domain.WithHTTPStatus(http.StatusUnauthorized),
		domain.WithScope(domain.ScopeRequest)))
}

// LoginThrottle throttles failed management-token authentication per client IP
// (ADR-SEC-06 §4.2): a token bucket of capacity Rate refilling Rate per
// Interval; each FAILED attempt consumes a token, a success resets the bucket.
// It is concurrency-safe and clock-injectable.
type LoginThrottle struct {
	rate     int
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	buckets map[string]*loginBucket
}

type loginBucket struct {
	tokens float64
	last   time.Time
}

// NewLoginThrottle builds the throttle. Rate <= 0 or Interval <= 0 disables it
// (nil), so the caller can attach it conditionally without a second check.
func NewLoginThrottle(rate int, interval time.Duration, now func() time.Time) *LoginThrottle {
	if rate <= 0 || interval <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &LoginThrottle{rate: rate, interval: interval, now: now, buckets: map[string]*loginBucket{}}
}

// Allow reports whether a request from ip may attempt authentication now. An
// exhausted bucket means the IP is in cooldown.
func (t *LoginThrottle) Allow(ip string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucketLocked(ip)
	return b.tokens >= 1
}

// Fail records a failed attempt, consuming one token.
func (t *LoginThrottle) Fail(ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucketLocked(ip)
	if b.tokens >= 1 {
		b.tokens--
	} else {
		b.tokens = 0
	}
}

// Success clears an IP's failure history after a valid token.
func (t *LoginThrottle) Success(ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.buckets, ip)
}

// RetryAfter is the cooldown until one token refills, for the 429 Retry-After
// header. It is the full interval when no tokens remain.
func (t *LoginThrottle) RetryAfter(ip string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucketLocked(ip)
	if b.tokens >= 1 {
		return 0
	}
	need := 1 - b.tokens
	return time.Duration(need / float64(t.rate) * float64(t.interval))
}

// bucketLocked returns the IP's bucket, refilling it for the elapsed time.
func (t *LoginThrottle) bucketLocked(ip string) *loginBucket {
	now := t.now()
	b, ok := t.buckets[ip]
	if !ok {
		b = &loginBucket{tokens: float64(t.rate), last: now}
		t.buckets[ip] = b
		return b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() / t.interval.Seconds() * float64(t.rate)
		if b.tokens > float64(t.rate) {
			b.tokens = float64(t.rate)
		}
		b.last = now
	}
	return b
}
