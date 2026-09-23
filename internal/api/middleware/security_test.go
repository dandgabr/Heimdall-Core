package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/observability"
)

// okHandler is the innermost handler every guard test wraps.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestHostGuard pins anti-DNS-rebinding (ADR-SEC-06 §3.1): loopback forms are
// accepted, public/rebinding names are rejected with 403, and the operator
// allowlist extends the accepted set exactly.
func TestHostGuard(t *testing.T) {
	h := HostGuard([]string{"router.local:8787"})

	tests := []struct {
		name string
		host string
		want int
	}{
		{"ipv4 loopback", "127.0.0.1:8787", http.StatusOK},
		{"localhost", "localhost:8787", http.StatusOK},
		{"localhost bare", "localhost", http.StatusOK},
		{"ipv6 loopback", "[::1]:8787", http.StatusOK},
		{"public name", "evil.com", http.StatusForbidden},
		{"rebinding name", "127.0.0.1.nip.io", http.StatusForbidden},
		{"allowlisted", "router.local:8787", http.StatusOK},
		{"empty host", "", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h(okHandler()).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusForbidden && !strings.Contains(rec.Body.String(), domain.CodeServerHostInvalid) {
				t.Fatalf("body = %q, want server.host_invalid", rec.Body.String())
			}
		})
	}
}

func TestHostAllowedDirect(t *testing.T) {
	if HostAllowed("evil.com", nil) {
		t.Fatal("public name accepted with no allowlist")
	}
	if !HostAllowed("LOCALHOST:1", nil) {
		t.Fatal("case-insensitive localhost rejected")
	}
	if !HostAllowed("Router.local", []string{"router.local:8787"}) {
		t.Fatal("allowlist entry rejected without port")
	}
}

// TestOriginGuard pins anti-CSRF (ADR-SEC-06 §3.2): a mutating management
// request with an external Origin/Referer is rejected; a loopback origin, an
// absent header (CLI), and a read-only request are admitted.
func TestOriginGuard(t *testing.T) {
	h := OriginGuard(nil)

	tests := []struct {
		name   string
		method string
		path   string
		origin string
		ref    string
		want   int
	}{
		{"external origin POST", http.MethodPost, "/api/mgmt/credentials", "https://evil.com", "", http.StatusForbidden},
		{"external referer DELETE", http.MethodDelete, "/api/mgmt/combos", "", "https://evil.com/x", http.StatusForbidden},
		{"loopback origin", http.MethodPost, "/api/mgmt/credentials", "http://127.0.0.1:8787", "", http.StatusOK},
		{"localhost origin", http.MethodPost, "/api/mgmt/credentials", "http://localhost:8787", "", http.StatusOK},
		{"no headers (CLI)", http.MethodPost, "/api/mgmt/credentials", "", "", http.StatusOK},
		{"GET is not checked", http.MethodGet, "/api/mgmt/ping", "https://evil.com", "", http.StatusOK},
		{"non-mgmt path not checked", http.MethodPost, "/v1/chat/completions", "https://evil.com", "", http.StatusOK},
		{"scheme-less origin", http.MethodPost, "/api/mgmt/x", "evil.com", "", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.ref != "" {
				req.Header.Set("Referer", tc.ref)
			}
			rec := httptest.NewRecorder()
			h(okHandler()).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestOriginGuardAllowlist(t *testing.T) {
	h := OriginGuard([]string{"https://trusted.example"})
	req := httptest.NewRequest(http.MethodPost, "/api/mgmt/x", nil)
	req.Header.Set("Origin", "https://trusted.example")
	rec := httptest.NewRecorder()
	h(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlisted origin rejected: %d", rec.Code)
	}
}

// TestCORSClosedByDefault is the acceptance criterion (ADR-SEC-06 §7.7): no
// wildcard is ever emitted, and only an explicitly allowlisted origin is echoed.
func TestCORSClosedByDefault(t *testing.T) {
	allowed := CORS([]string{"http://localhost:3000"})

	t.Run("allowed origin echoed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
			t.Fatalf("allow-origin = %q", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
			t.Fatal("wildcard emitted")
		}
	})

	t.Run("external origin gets no cors header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("external origin got a CORS header %q", got)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("simple request should still run: %d", rec.Code)
		}
	})

	t.Run("preflight from external origin refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("preflight status = %d, want 403", rec.Code)
		}
	})

	t.Run("preflight from allowed origin answered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Fatal("preflight missing allow-methods")
		}
	})

	t.Run("mgmt path never cors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/mgmt/x", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("management path emitted a CORS header")
		}
	})

	t.Run("non-v1 path skips cors entirely", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/other", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("non-v1 path emitted a CORS header")
		}
	})

	t.Run("wildcard in allowlist ignored", func(t *testing.T) {
		c := CORS([]string{"*"})
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()
		c(okHandler()).ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("wildcard allowlist entry admitted an origin")
		}
	})

	t.Run("no origin passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		rec := httptest.NewRecorder()
		allowed(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("emitted CORS without an Origin")
		}
	})
}

// TestExtractClientKey pins the transport contract (ADR-SEC-06 §2.2).
func TestExtractClientKey(t *testing.T) {
	cases := []struct {
		name, auth, apiKey, want string
	}{
		{"bearer", "Bearer k1", "", "k1"},
		{"bearer spaces", "Bearer   k1 ", "", "k1"},
		{"x-api-key", "", "k2", "k2"},
		{"none", "", "", ""},
		{"non-bearer", "Basic x", "", ""},
		{"bearer empty", "Bearer ", "", ""},
		{"bearer wins", "Bearer a", "b", "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.auth != "" {
				h.Set("Authorization", tc.auth)
			}
			if tc.apiKey != "" {
				h.Set("X-API-Key", tc.apiKey)
			}
			if got := ExtractClientKey(h); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientAuth covers the inference-gateway authentication contract
// (ADR-SEC-06 §2, §7.1-§7.4).
func TestClientAuth(t *testing.T) {
	verify := func(_ context.Context, presented string) (domain.ClientID, bool) {
		if presented == "good" {
			return "client-1", true
		}
		return "", false
	}

	t.Run("valid key admitted and identity injected", func(t *testing.T) {
		h := ClientAuth(verify, true)
		var seen string
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = ClientIDFrom(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h(inner).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if seen != "client-1" {
			t.Fatalf("injected client id = %q, want client-1", seen)
		}
	})

	t.Run("required and absent rejected", func(t *testing.T) {
		h := ClientAuth(verify, true)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), domain.CodeClientKeyInvalid) {
			t.Fatalf("body = %q", rec.Body.String())
		}
	})

	t.Run("invalid key rejected even when not required", func(t *testing.T) {
		h := ClientAuth(verify, false)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("absent key admitted when not required", func(t *testing.T) {
		h := ClientAuth(verify, false)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("key in query rejected", func(t *testing.T) {
		h := ClientAuth(verify, false)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions?api_key=good", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), domain.CodeInvalidRequest) {
			t.Fatalf("body = %q", rec.Body.String())
		}
	})

	t.Run("key in query rejected on read-only path too", func(t *testing.T) {
		h := ClientAuth(verify, true)
		req := httptest.NewRequest(http.MethodGet, "/v1/models?token=x", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (query keys forbidden on every /v1 path)", rec.Code)
		}
	})

	t.Run("read-only models not authenticated", func(t *testing.T) {
		h := ClientAuth(verify, true)
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (models is public)", rec.Code)
		}
	})

	t.Run("management path not authenticated by client key", func(t *testing.T) {
		h := ClientAuth(verify, true)
		req := httptest.NewRequest(http.MethodPost, "/api/mgmt/x", nil)
		rec := httptest.NewRecorder()
		h(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (client auth must not guard mgmt)", rec.Code)
		}
	})
}

// TestKeyInQueryDirect covers the parameter-name set.
func TestKeyInQueryDirect(t *testing.T) {
	q := func(rawQuery string) bool {
		req := httptest.NewRequest(http.MethodGet, "/v1/x?"+rawQuery, nil)
		return keyInQuery(req.URL.Query())
	}
	for _, name := range []string{"api_key", "apikey", "token", "key", "access_token"} {
		if !q(name + "=value") {
			t.Errorf("query %s=value not detected", name)
		}
	}
	if q("model=x") {
		t.Error("an ordinary param was flagged as a key")
	}
	if q("api_key=") {
		t.Error("an empty api_key was flagged")
	}
}

// TestLoginThrottle covers the per-IP failed-auth throttle (ADR-SEC-06 §4.2).
// TestLoginThrottle covers the windowed burst-then-cooldown model of
// ADR-SEC-06 §4.2: within a window, `limit` failures are allowed; the limit
// failure locks the IP for the FULL window (not a per-second refill).
func TestLoginThrottle(t *testing.T) {
	now := time.Unix(0, 0)
	th := NewLoginThrottle(2, time.Minute, func() time.Time { return now })

	// Two failures are permitted within the window.
	if !th.Allow("a") {
		t.Fatal("first attempt blocked")
	}
	th.Fail("a")
	if !th.Allow("a") {
		t.Fatal("second attempt blocked before the limit")
	}
	th.Fail("a")
	// The limit failure locks the IP for the FULL window.
	if th.Allow("a") {
		t.Fatal("attempt allowed after reaching the limit")
	}
	if ra := th.RetryAfter("a"); ra != time.Minute {
		t.Fatalf("retry-after = %v, want the full window (1m)", ra)
	}
	// A different IP has its own window.
	if !th.Allow("b") {
		t.Fatal("distinct IP blocked")
	}
	// Still locked just before the window elapses (no early refill).
	now = now.Add(59 * time.Second)
	if th.Allow("a") {
		t.Fatal("IP unlocked before the full cooldown elapsed")
	}
	// Unlocked once the full window has passed.
	now = now.Add(2 * time.Second)
	if !th.Allow("a") {
		t.Fatal("IP still locked after the cooldown")
	}
	// Success clears the history.
	th.Fail("a")
	th.Success("a")
	if !th.Allow("a") {
		t.Fatal("success did not reset the window")
	}
	if ra := th.RetryAfter("a"); ra != 0 {
		t.Fatalf("retry-after after success = %v, want 0", ra)
	}
}

// TestLoginThrottleWindowResetsAfterCooldown proves a fresh window starts after
// the lock lapses (a second burst is allowed).
func TestLoginThrottleWindowResetsAfterCooldown(t *testing.T) {
	now := time.Unix(0, 0)
	th := NewLoginThrottle(1, time.Minute, func() time.Time { return now })
	th.Fail("ip") // locks immediately (limit 1)
	if th.Allow("ip") {
		t.Fatal("locked IP allowed")
	}
	now = now.Add(time.Minute)
	if !th.Allow("ip") {
		t.Fatal("IP still locked after the window")
	}
	// A new failure in the fresh window locks again.
	th.Fail("ip")
	if th.Allow("ip") {
		t.Fatal("second burst not throttled")
	}
}

func TestLoginThrottleNilAndDisabled(t *testing.T) {
	if NewLoginThrottle(0, time.Minute, nil) != nil {
		t.Fatal("zero limit should disable the throttle")
	}
	if NewLoginThrottle(5, 0, nil) != nil {
		t.Fatal("zero window should disable the throttle")
	}
	// A nil clock falls back to time.Now (non-nil throttle).
	if NewLoginThrottle(5, time.Minute, nil) == nil {
		t.Fatal("a valid throttle with a nil clock must be built")
	}
	var th *LoginThrottle // nil
	if !th.Allow("x") {
		t.Fatal("nil throttle must allow")
	}
	th.Fail("x")    // must not panic
	th.Success("x") // must not panic
	if th.RetryAfter("x") != 0 {
		t.Fatal("nil throttle retry-after must be 0")
	}
}

// TestLoginThrottleDefaultIsADRWindow proves the shipped defaults are the ADR's
// "5 falhas/min, cooldown de 60s": five failures then a 60s Retry-After.
func TestLoginThrottleDefaultIsADRWindow(t *testing.T) {
	now := time.Unix(0, 0)
	th := NewLoginThrottle(5, time.Minute, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		if !th.Allow("ip") {
			t.Fatalf("attempt %d blocked before the limit", i)
		}
		th.Fail("ip")
	}
	if th.Allow("ip") {
		t.Fatal("sixth attempt allowed after 5 failures")
	}
	// The cooldown is the FULL 60s (the ADR's number), not 12s.
	if ra := th.RetryAfter("ip"); ra != 60*time.Second {
		t.Fatalf("retry-after = %v, want exactly 60s (ADR §4.2)", ra)
	}
}

// TestManagementAuthThrottle exercises the failed-auth throttle wired into the
// management guard: repeated failures return 429 with Retry-After, and the
// rejection carries the management-token code (ADR-SEC-06 §7.3).
func TestManagementAuthThrottle(t *testing.T) {
	now := time.Unix(0, 0)
	auth := ManagementAuth{
		Verify:   func(p string) bool { return p == "good" },
		Throttle: NewLoginThrottle(2, time.Minute, func() time.Time { return now }),
	}
	guarded := auth.Middleware(okHandler())

	fail := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer bad")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec
	}
	// Two failures reach the limit; the third is throttled before verify.
	for i := 0; i < 2; i++ {
		if rec := fail(); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status = %d, want 401", i, rec.Code)
		}
	}
	rec := fail()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third failure status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	if !strings.Contains(rec.Body.String(), domain.CodeQuotaRateLimited) {
		t.Fatalf("body = %q, want quota.rate_limited", rec.Body.String())
	}
	// A correct token from another IP still works (the throttle is per-IP).
	good := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	good.RemoteAddr = "127.0.0.2:6000"
	good.Header.Set("Authorization", "Bearer good")
	grec := httptest.NewRecorder()
	guarded.ServeHTTP(grec, good)
	if grec.Code != http.StatusOK {
		t.Fatalf("valid token from a fresh IP = %d, want 200", grec.Code)
	}
}

// TestManagementAuthEmitsTokenInvalidCode proves a rejected operator credential
// (or a client key misused as one) returns api.mgmt.token_invalid (ADR-SEC-06
// §7.3), not the generic error.unauthorized.
func TestManagementAuthEmitsTokenInvalidCode(t *testing.T) {
	auth := ManagementAuth{Verify: func(string) bool { return false }}
	rec := httptest.NewRecorder()
	auth.Middleware(okHandler()).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeManagementAuthFailed) {
		t.Fatalf("body = %q, want api.mgmt.token_invalid", rec.Body.String())
	}
}

// TestHostGuardCatchAllProtectsNewRoute is the SEC-06 §1.2 regression guard: a
// route registered later is protected because the guard wraps the WHOLE mux,
// never a per-path allowlist.
func TestHostGuardCatchAllProtectsNewRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/brand-new", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ran"))
	})
	h := HostGuard(nil)(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/brand-new", nil)
	req.Host = "evil.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("new route status = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ran") {
		t.Fatal("new route ran despite a bad Host")
	}
}

// TestWriteRateLimitedClampsSubSecond covers the secs<1 clamp: a cooldown under
// one second still emits Retry-After: 1.
func TestWriteRateLimitedClampsSubSecond(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	writeRateLimited(rec, req, 0)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeQuotaRateLimited) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestClientIDFrom covers the request accessor.
func TestClientIDFrom(t *testing.T) {
	if got := ClientIDFrom(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Fatalf("empty context = %q", got)
	}
	if got := ClientIDFrom(nil); got != "" {
		t.Fatalf("nil request = %q", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(observability.WithClientID(req.Context(), "c1"))
	if got := ClientIDFrom(req); got != "c1" {
		t.Fatalf("got %q, want c1", got)
	}
}
