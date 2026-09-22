package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
