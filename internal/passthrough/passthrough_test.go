package passthrough

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeUpstream returns an httptest server behaving like an OpenAI-compatible
// endpoint. It records whether it saw the forwarded credential so the test can
// assert the header is set without ever logging it.
func fakeUpstream(t *testing.T) (*httptest.Server, *bool) {
	t.Helper()
	gotAuth := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			gotAuth = true
		}
		var body struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)
			for _, line := range []string{
				"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
				"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
				"data: [DONE]\n\n",
			} {
				_, _ = w.Write([]byte(line))
				flusher.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Hello"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

func mustClient(t *testing.T, cfg ClientConfig) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// loopbackBaseURL converts an httptest URL (127.0.0.1) into an allowed upstream:
// it is already a loopback IP literal, so plain HTTP is permitted.
func loopbackBaseURL(srv *httptest.Server) string { return srv.URL }

func TestCompleteNonStream(t *testing.T) {
	srv, gotAuth := fakeUpstream(t)
	client := mustClient(t, ClientConfig{BaseURL: loopbackBaseURL(srv), APIKey: "sk-test"})

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
	out, err := client.Complete(context.Background(), body)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(string(out), "Hello") {
		t.Errorf("unexpected body: %s", out)
	}
	if !*gotAuth {
		t.Error("upstream did not receive the credential")
	}
}

func TestStreamRelaysSSE(t *testing.T) {
	srv, _ := fakeUpstream(t)
	client := mustClient(t, ClientConfig{BaseURL: loopbackBaseURL(srv), APIKey: "sk-test"})

	body := []byte(`{"model":"gpt-4","stream":true,"messages":[]}`)
	rec := httptest.NewRecorder()
	result, err := client.Stream(context.Background(), body, rec)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !result.Committed {
		t.Error("stream must be committed after a 2xx")
	}
	if result.Bytes == 0 {
		t.Error("no bytes relayed")
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("content-type = %q, want text/event-stream", got)
	}
	out := rec.Body.String()
	for _, want := range []string{"Hel", "lo", "[DONE]"} {
		if !strings.Contains(out, want) {
			t.Errorf("stream body missing %q: %s", want, out)
		}
	}
}

func TestStreamUpstreamErrorNotCommitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key sk-secret-123"}`))
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL, APIKey: "sk-test"})
	body := []byte(`{"model":"gpt-4","stream":true}`)
	rec := httptest.NewRecorder()

	result, err := client.Stream(context.Background(), body, rec)
	if err == nil {
		t.Fatal("expected error for upstream 401")
	}
	if result.Committed {
		t.Error("must not be committed when the upstream rejects before any byte")
	}
}

func TestCompleteContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Complete(ctx, []byte(`{"model":"gpt-4"}`))
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestReadStreamFlag(t *testing.T) {
	model, stream, err := readStreamFlag([]byte(`{"model":"gpt-4","stream":true}`))
	if err != nil {
		t.Fatalf("readStreamFlag: %v", err)
	}
	if model != "gpt-4" || !stream {
		t.Errorf("got model=%q stream=%v", model, stream)
	}
}

func TestEndpointTrimsTrailingSlash(t *testing.T) {
	c := mustClient(t, ClientConfig{BaseURL: "https://example.com/v1/"})
	if got := c.endpoint(); got != "https://example.com/v1/chat/completions" {
		t.Errorf("endpoint = %q", got)
	}
}

// --- P1-5: size limit, HTTPS policy, redirect block, SSRF guard ---

func TestCompleteRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL, MaxResponseBytes: 1024})
	_, err := client.Complete(context.Background(), []byte(`{"model":"gpt-4"}`))
	if err == nil {
		t.Fatal("expected an error for a response over the limit")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamResponseTooLarge {
		t.Fatalf("err = %v, want %s", err, domain.CodeUpstreamResponseTooLarge)
	}
}

func TestCompleteAllowsResponseAtLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer srv.Close()

	client := mustClient(t, ClientConfig{BaseURL: srv.URL, MaxResponseBytes: 1024})
	out, err := client.Complete(context.Background(), []byte(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("Complete at the exact limit: %v", err)
	}
	if len(out) != 1024 {
		t.Errorf("len = %d, want 1024", len(out))
	}
}

func TestNewClientRejectsPlainHTTPNonLoopback(t *testing.T) {
	_, err := NewClient(ClientConfig{BaseURL: "http://api.example.com/v1"})
	if err == nil {
		t.Fatal("expected rejection of plain HTTP to a non-loopback host")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamInsecureURL {
		t.Fatalf("err = %v, want %s", err, domain.CodeUpstreamInsecureURL)
	}
}

func TestNewClientAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	if _, err := NewClient(ClientConfig{BaseURL: "https://api.example.com/v1"}); err != nil {
		t.Errorf("HTTPS upstream rejected: %v", err)
	}
	if _, err := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:11434/v1"}); err != nil {
		t.Errorf("loopback HTTP upstream rejected: %v", err)
	}
	if _, err := NewClient(ClientConfig{BaseURL: "ftp://api.example.com"}); err == nil {
		t.Error("expected rejection of an unsupported scheme")
	}
}

func TestClientDoesNotFollowRedirect(t *testing.T) {
	var targetHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	client := mustClient(t, ClientConfig{BaseURL: redirector.URL, APIKey: "sk-test"})
	_, err := client.Complete(context.Background(), []byte(`{"model":"gpt-4"}`))
	if err == nil {
		t.Fatal("expected the redirect to surface as an upstream error")
	}
	if targetHit {
		t.Error("client followed the redirect to an unvalidated destination")
	}
}
