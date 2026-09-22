package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/observability"
)

// TestLocalOnlyProtectsNewlyAddedRoute is the regression guard for SEC-04: a
// route registered later must be protected without any per-route change. The
// mux is wrapped wholesale, exactly as app.Handler does it.
func TestLocalOnlyProtectsNewlyAddedRoute(t *testing.T) {
	mux := http.NewServeMux()
	// A brand-new "dangerous" route added by a future phase.
	mux.HandleFunc("POST /v1/new-spawn-capable", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("executed"))
	})

	handler := LocalOnly(mux)

	t.Run("remote peer rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/new-spawn-capable", nil)
		req.RemoteAddr = "203.0.113.7:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if body := rec.Body.String(); !contains(body, "error.forbidden_local_only") {
			t.Errorf("body = %q, want the i18n code", body)
		}
		if body := rec.Body.String(); contains(body, "executed") {
			t.Error("handler ran for a remote peer")
		}
	})

	t.Run("loopback peer allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/new-spawn-capable", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Body.String() != "executed" {
			t.Errorf("body = %q, want executed", rec.Body.String())
		}
	})

	t.Run("ipv6 loopback allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/new-spawn-capable", nil)
		req.RemoteAddr = "[::1]:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

func TestIsLoopbackRemoteFailClosed(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:1234":  true,
		"[::1]:1234":      true,
		"localhost:1234":  true,
		"203.0.113.7:100": false,
		"":                false,
		"garbage":         false,
		"0.0.0.0:100":     false,
	}
	for addr, want := range tests {
		if got := IsLoopbackRemote(addr); got != want {
			t.Errorf("IsLoopbackRemote(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestManagementAuthConstantTimeCompare(t *testing.T) {
	auth := ManagementAuth{Verify: func(p string) bool { return p == "secret-token" }}
	guarded := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("bearer token accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("custom header accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.Header.Set("X-Management-Token", "secret-token")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("missing token rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("wrong token rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestErrorEnvelope(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
		wantKey  string
	}{
		{"not found", http.MethodGet, "/nope", http.StatusNotFound, "error.not_found"},
		{"method not allowed", http.MethodPost, "/health", http.StatusMethodNotAllowed, "error.method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			ErrorEnvelope(mux).ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("content-type = %q", ct)
			}
			if !strings.Contains(rec.Body.String(), tt.wantKey) {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantKey)
			}
		})
	}
}

// TestErrorEnvelopeLeavesHandlerJSONUntouched ensures the wrapper does not
// rewrite a response a handler already produced in the envelope format.
func TestErrorEnvelopeLeavesHandlerJSONUntouched(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rec := httptest.NewRecorder()
	ErrorEnvelope(mux).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("body = %q, want the handler payload untouched", rec.Body.String())
	}
}

// TestRequestIDMiddleware covers the 0%-covered RequestID wrapper.
func TestRequestIDMiddleware(t *testing.T) {
	var seen string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = observability.RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := RequestID(func() domain.RequestID { return domain.RequestID("fixed-id") })(inner)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-ID") != "fixed-id" {
		t.Errorf("X-Request-ID = %q", rec.Header().Get("X-Request-ID"))
	}
	if seen != "fixed-id" {
		t.Errorf("context request id = %q", seen)
	}
}

// TestRecovererConvertsPanicTo500 covers the Recoverer wrapper and asserts the
// panic never reaches the client.
func TestRecovererConvertsPanicTo500(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom-secret-panic-value")
	})
	h := Recoverer(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "kaboom-secret-panic-value") {
		t.Fatalf("panic value leaked to the client: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error.internal") {
		t.Errorf("body = %s, want error.internal", rec.Body.String())
	}
}

// TestRecovererNilLoggerStillRecovers proves a nil logger does not panic during
// recovery.
func TestRecovererNilLoggerStillRecovers(t *testing.T) {
	h := Recoverer(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("x")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestConstantTimeEqual covers the exported comparison helper.
func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings reported unequal")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Error("different strings reported equal")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Error("different-length strings reported equal")
	}
	if !ConstantTimeEqual("", "") {
		t.Error("empty strings reported unequal")
	}
}

// TestAsDomainErrorNonDomain covers the non-DomainError branch.
func TestAsDomainErrorNonDomain(t *testing.T) {
	de := asDomainError(errors.New("plain"))
	if de.Code != domain.CodeInternal {
		t.Errorf("code = %q, want error.internal", de.Code)
	}
	// A nil error is a 500 internal too.
	if got := asDomainError(nil); got.Code != domain.CodeInternal {
		t.Errorf("nil error code = %q", got.Code)
	}
	// A wrapped DomainError is unwrapped.
	wrapped := fmt.Errorf("wrap: %w", domain.New("some.code", domain.WithHTTPStatus(418)))
	if got := asDomainError(wrapped); got.Code != "some.code" || got.HTTPStatus != 418 {
		t.Errorf("wrapped DomainError = %+v", got)
	}
}

// TestWriteErrorNilError covers the nil-error branch (asDomainError(nil) -> 500)
// and the empty-params path.
func TestWriteErrorNilError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "error.internal") {
		t.Errorf("body = %s, want error.internal", rec.Body.String())
	}
}

// TestEnvelopeWriterInformedSecondCall covers the "informed" guard: a second
// WriteHeader must be ignored rather than write a second status line.
func TestEnvelopeWriterInformedSecondCall(t *testing.T) {
	rec := httptest.NewRecorder()
	ew := &envelopeWriter{ResponseWriter: rec, request: httptest.NewRequest(http.MethodGet, "/x", nil)}
	ew.WriteHeader(http.StatusNotFound)
	// A second call must be a no-op (the guard sets informed on the first).
	ew.WriteHeader(http.StatusTeapot)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the first (404)", rec.Code)
	}
}

// TestWriteErrorZeroStatusDomainError covers the status==0 branch on a real
// DomainError (not just the nil-error path): a DomainError built without
// WithHTTPStatus defaults to 500 in New, so construct one with an explicit zero.
func TestWriteErrorZeroStatusDomainError(t *testing.T) {
	rec := httptest.NewRecorder()
	de := &domain.DomainError{Code: "x.zero", HTTPStatus: 0}
	WriteError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), de)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestWriteErrorDefaultStatus covers the zero-status fallback.
func TestWriteErrorDefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	WriteError(rec, req, domain.New("x.no_status"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestExtractTokenBareAuthorization covers the non-Bearer Authorization branch.
func TestExtractTokenBareAuthorization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "  raw-token  ")
	if got := extractToken(req); got != "raw-token" {
		t.Errorf("extractToken = %q, want raw-token", got)
	}
	// X-Management-Token fallback.
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("X-Management-Token", " mgmt ")
	if got := extractToken(req2); got != "mgmt" {
		t.Errorf("extractToken = %q, want mgmt", got)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
