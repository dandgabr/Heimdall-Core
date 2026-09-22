package passthrough

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestSSRFControlDeniesPrivateDestinations(t *testing.T) {
	allow := func(network, address string) error {
		return ssrfControl(false)("tcp", address, nil)
	}

	tests := map[string]bool{
		"127.0.0.1:80":                true, // loopback denied when allowLoopback=false
		"169.254.169.254:80":          true, // cloud metadata
		"10.0.0.5:80":                 true,
		"192.168.1.10:80":             true,
		"172.16.5.4:80":               true,
		"[::1]:80":                    true,
		"[fe80::1]:80":                true,
		"[::ffff:169.254.169.254]:80": true, // IPv4-mapped metadata
		"93.184.216.34:80":            false,
		"8.8.8.8:53":                  false,
	}
	for addr, wantDenied := range tests {
		err := allow("tcp", addr)
		if wantDenied && err == nil {
			t.Errorf("%s: expected denial", addr)
		}
		if !wantDenied && err != nil {
			t.Errorf("%s: unexpected denial: %v", addr, err)
		}
	}
}

func TestSSRFControlAllowsExplicitLoopback(t *testing.T) {
	err := ssrfControl(true)("tcp", "127.0.0.1:11434", nil)
	if err != nil {
		t.Errorf("loopback should be allowed for a loopback upstream: %v", err)
	}
}

// TestDeniedIPRange covers every denied range plus the allow-loopback exception,
// including the IPv6 forms the SSRF guard must collapse.
func TestDeniedIPRange(t *testing.T) {
	tests := []struct {
		ip            string
		allowLoopback bool
		wantDenied    bool
	}{
		{"127.0.0.1", false, true},
		{"127.0.0.1", true, false},
		{"::1", false, true},
		{"::1", true, false},
		{"10.0.0.1", false, true},
		{"172.16.0.1", false, true},
		{"192.168.1.1", false, true},
		{"169.254.169.254", false, true},        // cloud metadata
		{"::ffff:169.254.169.254", false, true}, // IPv4-mapped metadata
		{"::ffff:127.0.0.1", true, false},       // mapped loopback allowed
		{"fe80::1", false, true},                // link-local
		{"ff02::1", false, true},                // link-local multicast
		{"224.0.0.1", false, true},              // multicast
		{"0.0.0.0", false, true},                // unspecified
		{"::", false, true},                     // unspecified v6
		{"ff01::1", false, true},                // interface-local multicast
		{"93.184.216.34", false, false},         // public
		{"8.8.8.8", false, false},
	}
	for _, tt := range tests {
		addr, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.ip, err)
		}
		if got := deniedIP(addr, tt.allowLoopback); got != tt.wantDenied {
			t.Errorf("deniedIP(%s, allow=%v) = %v, want %v", tt.ip, tt.allowLoopback, got, tt.wantDenied)
		}
	}
	// An invalid address fails closed.
	if !deniedIP(netip.Addr{}, false) {
		t.Error("invalid IP was not denied")
	}
}

// TestSSRFControlNonLiteralHostFailsClosed covers the ParseAddr-error branch.
func TestSSRFControlNonLiteralHostFailsClosed(t *testing.T) {
	// A hostname (not an IP literal) cannot be validated; fail closed.
	err := ssrfControl(false)("tcp", "example.com:80", nil)
	if err == nil {
		t.Fatal("non-literal host accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamDestinationDenied {
		t.Fatalf("err = %v, want upstream.destination_denied", err)
	}
}

// TestSSRFControlAddressWithoutPort covers the SplitHostPort-error fallback.
func TestSSRFControlAddressWithoutPort(t *testing.T) {
	if err := ssrfControl(false)("tcp", "8.8.8.8", nil); err != nil {
		t.Errorf("bare public IP rejected: %v", err)
	}
}

// TestValidateUpstreamURLEdges covers the no-host, bad-URL and unsupported
// scheme branches directly.
func TestValidateUpstreamURLEdges(t *testing.T) {
	if _, err := validateUpstreamURL("http://"); err == nil {
		t.Error("URL with no host accepted")
	}
	if _, err := validateUpstreamURL("://bad"); err == nil {
		t.Error("unparseable URL accepted")
	}
	if _, err := validateUpstreamURL("ftp://example.com"); err == nil {
		t.Error("unsupported scheme accepted")
	}
	// https with a host is allowed and does not enable loopback.
	if loop, err := validateUpstreamURL("https://example.com/v1"); err != nil || loop {
		t.Errorf("https public = loop=%v err=%v", loop, err)
	}
	// https loopback enables the exception.
	if loop, err := validateUpstreamURL("https://127.0.0.1/v1"); err != nil || !loop {
		t.Errorf("https loopback = loop=%v err=%v", loop, err)
	}
}

// TestIsLoopbackLiteral covers the literal parser directly.
func TestIsLoopbackLiteral(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"[::1]":     true,
		"localhost": false, // a name, never accepted here
		"10.0.0.1":  false,
		"":          false,
		"garbage":   false,
	}
	for host, want := range cases {
		if got := IsLoopbackLiteral(host); got != want {
			t.Errorf("IsLoopbackLiteral(%q) = %v, want %v", host, got, want)
		}
	}
}
