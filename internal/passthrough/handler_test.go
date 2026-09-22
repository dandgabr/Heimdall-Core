package passthrough

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newHandlerServer builds an upstream fake plus the passthrough handler mounted
// on a mux, exercising the real route (previously 0% covered).
func newHandlerServer(t *testing.T) (*httptest.Server, *httptest.Server, *bool) {
	t.Helper()
	upstream, gotAuth := fakeUpstream(t)
	client := mustClient(t, ClientConfig{BaseURL: upstream.URL, APIKey: "sk-test"})
	mux := http.NewServeMux()
	NewHandler(client).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, upstream, gotAuth
}

func TestHandlerNonStream(t *testing.T) {
	srv, _, gotAuth := newHandlerServer(t)

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !*gotAuth {
		t.Error("upstream did not receive the credential")
	}
}

func TestHandlerStream(t *testing.T) {
	srv, _, _ := newHandlerServer(t)

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","stream":true}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestHandlerInvalidJSON(t *testing.T) {
	srv, _, _ := newHandlerServer(t)

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerBodyTooLarge(t *testing.T) {
	srv, _, _ := newHandlerServer(t)

	big := strings.Repeat("a", MaxRequestBytes+2)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions",
		strings.NewReader(big))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestHandlerUpstreamError(t *testing.T) {
	// An upstream that always fails: the handler must surface it as an error
	// envelope, not a 500 panic.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	client := mustClient(t, ClientConfig{BaseURL: bad.URL})
	mux := http.NewServeMux()
	NewHandler(client).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want JSON", ct)
	}
}

// TestHandlerReadBodyError covers the body-read error branch with a reader that
// always fails.
func TestHandlerReadBodyError(t *testing.T) {
	client := mustClient(t, ClientConfig{BaseURL: "http://127.0.0.1:1"})
	h := NewHandler(client)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", failingReader{})
	rec := httptest.NewRecorder()
	h.chatCompletions(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errReadFailed }

var errReadFailed = &readError{}

type readError struct{}

func (*readError) Error() string { return "read failed" }
