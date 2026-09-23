package mgmt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
)

const testToken = "management-token-value"

func newTestMux(verify middleware.ManagementAuth) *http.ServeMux {
	mux := http.NewServeMux()
	New(verify, nil).Register(mux)
	return mux
}

func alwaysValid(presented string) bool { return presented == testToken }

func TestPingWithValidToken(t *testing.T) {
	mux := newTestMux(middleware.ManagementAuth{Verify: alwaysValid})

	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["code"] != "api.ping_ok" {
		t.Errorf("code = %v, want api.ping_ok", body["code"])
	}
}

func TestPingWithoutTokenIsUnauthorized(t *testing.T) {
	mux := newTestMux(middleware.ManagementAuth{Verify: alwaysValid})

	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "error.unauthorized") {
		t.Errorf("body = %q, want error.unauthorized", rec.Body.String())
	}
}

func TestPingWithWrongTokenIsUnauthorized(t *testing.T) {
	mux := newTestMux(middleware.ManagementAuth{Verify: alwaysValid})

	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	req.Header.Set("Authorization", "Bearer not-the-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestPingFailsClosedWithoutVerifier ensures a missing verifier is not treated
// as "no auth required".
func TestPingFailsClosedWithoutVerifier(t *testing.T) {
	mux := newTestMux(middleware.ManagementAuth{})

	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/ping", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
