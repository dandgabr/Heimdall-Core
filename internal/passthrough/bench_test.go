package passthrough

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file is measurement-only: it benchmarks the streaming relay and the
// request-body parse. No production code is touched.
//
//	go test ./internal/passthrough -bench . -benchmem -count=5

// benchSSEEvent is one realistic OpenAI-compatible SSE data frame.
var benchSSEEvent = []byte(`data: {"choices":[{"delta":{"content":"benchmark token text here"}}]}` + "\n\n")

// benchSSEUpstream returns a loopback SSE upstream that emits chunks events.
func benchSSEUpstream(b *testing.B, chunks int) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write(benchSSEEvent); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	b.Cleanup(srv.Close)
	return srv
}

func benchClient(b *testing.B, upstream string) *Client {
	b.Helper()
	c, err := NewClient(ClientConfig{
		BaseURL:               upstream,
		APIKey:                "sk-bench-not-a-real-key",
		ResponseHeaderTimeout: 10 * time.Second,
	})
	if err != nil {
		b.Fatalf("NewClient: %v", err)
	}
	return c
}

// benchDiscardWriter is a minimal downstream sink: it implements
// http.ResponseWriter and http.Flusher but throws the bytes away, so the
// benchmark measures the relay itself rather than a recorder buffer growing over
// the iterations. (The suite's own discardWriter has no Flush, which would hide
// the per-chunk flush cost.)
type benchDiscardWriter struct {
	h http.Header
}

func newBenchDiscardWriter() *benchDiscardWriter {
	return &benchDiscardWriter{h: make(http.Header)}
}

func (d *benchDiscardWriter) Header() http.Header         { return d.h }
func (d *benchDiscardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *benchDiscardWriter) WriteHeader(int)             {}
func (d *benchDiscardWriter) Flush()                      {}

// BenchmarkStreamRelay measures the full client-side relay of N chunks: upstream
// request, commit on first byte, per-chunk copy through the bounded channel and
// the downstream write.
func BenchmarkStreamRelay(b *testing.B) {
	const chunks = 200
	srv := benchSSEUpstream(b, chunks)
	client := benchClient(b, srv.URL)
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	// One warm-up run to learn the relayed byte count (TCP may coalesce frames,
	// so the total is measured, not assumed).
	warm, err := client.Stream(context.Background(), body, newBenchDiscardWriter())
	if err != nil {
		b.Fatalf("warm-up Stream: %v", err)
	}
	b.SetBytes(warm.Bytes)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := client.Stream(context.Background(), body, newBenchDiscardWriter()); err != nil {
			b.Fatalf("Stream: %v", err)
		}
	}
}

// BenchmarkHandlerStreamEndToEnd drives the whole F0 path over loopback TCP on
// both sides: client -> handler -> upstream -> relay back. It is the throughput
// number a real streaming request pays.
func BenchmarkHandlerStreamEndToEnd(b *testing.B) {
	const chunks = 200
	upstream := benchSSEUpstream(b, chunks)
	client := benchClient(b, upstream.URL)

	mux := http.NewServeMux()
	NewHandler(client).Register(mux)
	front := httptest.NewServer(mux)
	b.Cleanup(front.Close)

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			b.Fatalf("POST: %v", err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatalf("drain: %v", err)
		}
		_ = resp.Body.Close()
	}
}

// BenchmarkReadStreamFlag is the pure request-body parse that runs once per
// request, before any I/O.
func BenchmarkReadStreamFlag(b *testing.B) {
	body := []byte(`{"model":"gpt-4o-mini","stream":true,` +
		`"messages":[{"role":"user","content":"hello world, this is a benchmark"}]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := readStreamFlag(body); err != nil {
			b.Fatalf("readStreamFlag: %v", err)
		}
	}
}
