package openai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/i18n"
)

func newTestHandler() *Handler { return New(i18n.MustNew(), nil) }

func TestHealth(t *testing.T) {
	mux := http.NewServeMux()
	newTestHandler().Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["code"] != "api.health_ok" {
		t.Errorf("code = %v, want api.health_ok", body["code"])
	}
}

// TestModelsShape pins the OpenAI-compatible envelope: an object list with a
// present (never null) data array even when there is no catalog.
func TestModelsShape(t *testing.T) {
	mux := http.NewServeMux()
	newTestHandler().Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Object string `json:"object"`
		Data   []any  `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Object != "list" {
		t.Errorf("object = %q, want list", body.Object)
	}
	if body.Data == nil {
		t.Error("data must be an empty array, not null")
	}
	if len(body.Data) != 0 {
		t.Errorf("len(data) = %d, want 0", len(body.Data))
	}
}

// TestModelsListsCatalog proves the catalog is served in the OpenAI model shape:
// one entry per declared model, object "model" and the declaring provider as
// owned_by, in the catalog's deterministic order.
func TestModelsListsCatalog(t *testing.T) {
	catalog := StaticCatalog{
		{ID: "gpt-oss:120b", Owner: "ollama-cloud"},
		{ID: "glm-4.6", Owner: "z.ai"},
	}
	mux := http.NewServeMux()
	New(i18n.MustNew(), catalog).Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Object string       `json:"object"`
		Data   []modelEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Object != "list" {
		t.Errorf("object = %q, want list", body.Object)
	}
	want := []modelEntry{
		{ID: "gpt-oss:120b", Object: "model", OwnedBy: "ollama-cloud"},
		{ID: "glm-4.6", Object: "model", OwnedBy: "z.ai"},
	}
	if len(body.Data) != len(want) {
		t.Fatalf("len(data) = %d, want %d", len(body.Data), len(want))
	}
	for i := range want {
		if body.Data[i] != want[i] {
			t.Errorf("data[%d] = %+v, want %+v", i, body.Data[i], want[i])
		}
	}
}

// TestModelsEmptyCatalogIsEmptyArray proves a nil catalog still yields [].
func TestModelsEmptyCatalogIsEmptyArray(t *testing.T) {
	mux := http.NewServeMux()
	New(i18n.MustNew(), nil).Register(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if got := rec.Body.String(); !contains(got, `"data":[]`) {
		t.Errorf("body = %s, want an empty data array", got)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func TestRoutesAreMethodScoped(t *testing.T) {
	mux := http.NewServeMux()
	newTestHandler().Register(mux)

	// Register uses the Go 1.22 method pattern, so a POST must not reach the
	// GET handler; the mux answers 405 itself.
	req := httptest.NewRequest(http.MethodPost, "/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/models status = %d, want 405", rec.Code)
	}
}
