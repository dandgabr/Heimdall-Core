package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// captureDoer records the last request and replies with a canned response.
type captureDoer struct {
	status  int
	body    string
	err     error
	lastReq *http.Request
	last    []byte
}

func (c *captureDoer) Do(req *http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	c.lastReq = req
	c.last, _ = io.ReadAll(req.Body)
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestNewHTTPEmbedderGuards(t *testing.T) {
	if NewHTTPEmbedder(EmbedderConfig{}) != nil {
		t.Fatal("an empty config must keep the engine OFF")
	}
	if NewHTTPEmbedder(EmbedderConfig{BaseURL: "https://api.example.com", Model: "m"}) != nil {
		t.Fatal("a non-positive dim must keep the engine OFF")
	}
	// A policy-invalid destination (cleartext http to a public host) keeps the
	// engine OFF — the egress authority is the gatekeeper (ADR-SEC-05).
	if NewHTTPEmbedder(EmbedderConfig{BaseURL: "http://api.example.com", Model: "m", Dim: 4}) != nil {
		t.Fatal("a non-HTTPS endpoint must keep the engine OFF")
	}
	// HTTPS with the default policy builds.
	e := NewHTTPEmbedder(EmbedderConfig{BaseURL: "https://api.example.com/v1", Model: "m", Dim: 4})
	if e == nil {
		t.Fatal("a valid HTTPS opt-in must build")
	}
	if e.endpoint != "https://api.example.com/v1/embeddings" {
		t.Fatalf("endpoint = %s", e.endpoint)
	}
	if e.ID() != "http:m" || e.Dim() != 4 {
		t.Fatalf("id/dim = %s/%d", e.ID(), e.Dim())
	}
}

// TestHTTPEmbedderRedactsBeforeEgress is the privacy assertion: the payload
// that leaves the process carries the REDACTED content, never the raw prompt.
func TestHTTPEmbedderRedactsBeforeEgress(t *testing.T) {
	doer := &captureDoer{body: `{"data":[{"embedding":[0.5,0.5,0.5,0.5],"index":0}]}`}
	e := NewHTTPEmbedder(EmbedderConfig{
		BaseURL:   "https://api.example.com/v1",
		Model:     "embed-1",
		Dim:       4,
		APIKeyEnv: "HEIMDALL_TEST_EMBED_KEY",
		Doer:      doer,
	})
	t.Setenv("HEIMDALL_TEST_EMBED_KEY", "sekret-key-123")

	vec, err := e.Embed(context.Background(), "token abcdef123456 remember this")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(vec) != 4 || vec[0] != 0.5 {
		t.Fatalf("vec = %v", vec)
	}
	if doer.lastReq.Method != http.MethodPost || doer.lastReq.URL.String() != "https://api.example.com/v1/embeddings" {
		t.Fatalf("request = %s %s", doer.lastReq.Method, doer.lastReq.URL)
	}
	if got := doer.lastReq.Header.Get("Authorization"); got != "Bearer sekret-key-123" {
		t.Fatalf("authorization = %q", got)
	}
	var sent embedRequest
	if err := json.Unmarshal(doer.last, &sent); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if sent.Model != "embed-1" || len(sent.Input) != 1 {
		t.Fatalf("payload = %s", doer.last)
	}
	if strings.Contains(sent.Input[0], "abcdef123456") {
		t.Fatalf("RAW content left the process: %q", sent.Input[0])
	}
	if !strings.Contains(sent.Input[0], "[REDACTED]") {
		t.Fatalf("redaction missing: %q", sent.Input[0])
	}
	if bytes.Contains(doer.last, []byte("sekret-key-123")) {
		t.Fatal("the key must never appear in the body")
	}
}

// TestHTTPEmbedderErrorPaths covers every failure branch.
func TestHTTPEmbedderErrorPaths(t *testing.T) {
	cases := []struct {
		name string
		doer *captureDoer
	}{
		{"transport error", &captureDoer{err: context.Canceled}},
		{"http 500", &captureDoer{status: 500, body: "boom"}},
		{"bad json", &captureDoer{body: "{not json"}},
		{"empty data", &captureDoer{body: `{"data":[]}`}},
		{"dim mismatch", &captureDoer{body: `{"data":[{"embedding":[1,2]}]}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewHTTPEmbedder(EmbedderConfig{
				BaseURL: "https://api.example.com", Model: "m", Dim: 4, Doer: tc.doer,
			})
			if _, err := e.Embed(context.Background(), "content"); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// TestHTTPEmbedderNoKeyStillSendsUnsigned covers the missing-API-key branch:
// the call proceeds WITHOUT the Authorization header (a local or keyless
// endpoint is a valid operator choice) — it never fails for an absent key.
func TestHTTPEmbedderNoKeyStillSendsUnsigned(t *testing.T) {
	doer := &captureDoer{body: `{"data":[{"embedding":[1,1,1,1]}]}`}
	e := NewHTTPEmbedder(EmbedderConfig{
		BaseURL: "https://api.example.com", Model: "m", Dim: 4, Doer: doer,
	})
	if _, err := e.Embed(context.Background(), "c"); err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if doer.lastReq.Header.Get("Authorization") != "" {
		t.Fatal("no key configured: the header must be absent")
	}
}
