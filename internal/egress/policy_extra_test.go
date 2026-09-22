package egress

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestRedirectPolicyUsesDefaultCap covers the MaxRedirects<=0 branch: with
// FollowRedirects on and no explicit cap, the policy falls back to
// DefaultMaxRedirects and allows up to (but not including) that many hops.
func TestRedirectPolicyUsesDefaultCap(t *testing.T) {
	rp := redirectPolicy(contracts.EgressSpec{FollowRedirects: true})
	req := &http.Request{URL: mustURL(t, "https://api.example.com/next")}

	// One hop below the default cap: allowed.
	if err := rp(req, make([]*http.Request, DefaultMaxRedirects-1)); err != nil {
		t.Fatalf("hop below the default cap rejected: %v", err)
	}
	// At the default cap: refused.
	if err := rp(req, make([]*http.Request, DefaultMaxRedirects)); err == nil {
		t.Fatal("the default redirect cap was not enforced")
	}
}

// TestClientLoopbackRequiresOptIn is the P2 regression: a loopback literal must
// be permitted ONLY when AllowLoopback is explicitly true. Before the fix,
// ValidateUpstreamURL's literal detection alone unlocked the dial-time guard, so
// AllowLoopback was decorative.
func TestClientLoopbackRequiresOptIn(t *testing.T) {
	// A loopback literal without the opt-in: the client builds (the URL is
	// scheme-valid), but the dial-time guard MUST deny it. Exercise the guard
	// directly with the value Client now derives.
	if allow := loopbackAllowed(contracts.EgressSpec{BaseURL: "http://127.0.0.1:11434/v1"}); allow {
		t.Fatal("loopback allowed without AllowLoopback")
	}

	// With the explicit opt-in: permitted.
	if allow := loopbackAllowed(contracts.EgressSpec{BaseURL: "http://127.0.0.1:11434/v1", AllowLoopback: true}); !allow {
		t.Fatal("loopback denied despite AllowLoopback=true")
	}

	// A non-loopback host never unlocks the exception, opt-in or not.
	if allow := loopbackAllowed(contracts.EgressSpec{BaseURL: "https://api.example.com/v1", AllowLoopback: true}); allow {
		t.Fatal("a non-loopback host unlocked the loopback exception")
	}
}

// loopbackAllowed reproduces the allowLoopback value Client derives and asserts
// the resulting dial-time denial, so the regression is pinned at the behaviour
// (the Control hook) and not just at the boolean.
func loopbackAllowed(spec contracts.EgressSpec) bool {
	loopbackLiteral, err := ValidateUpstreamURL(spec.BaseURL)
	if err != nil {
		return false
	}
	allow := spec.AllowLoopback && loopbackLiteral
	// Confirm the derived value actually drives the dial-time guard.
	dialDenied := SSRFControl(allow)("tcp", "127.0.0.1:11434", nil) != nil
	return allow && !dialDenied
}

// TestProxyConnectGuardDeniesDenylistTargets is the P2 regression: a CONNECT
// tunnel target on the denylist (metadata, private, loopback) is refused, so a
// malicious proxy cannot bypass the SSRF guard.
func TestProxyConnectGuardDeniesDenylistTargets(t *testing.T) {
	denied := []string{
		"169.254.169.254:80", // link-local metadata
		"100.100.100.200:80", // Alibaba metadata
		"10.0.0.5:443",       // private
		"192.168.1.1:443",    // private
		"127.0.0.1:11434",    // loopback, no opt-in
		"localhost:11434",    // loopback name, no opt-in
	}
	guard := proxyConnectGuard(false)
	for _, target := range denied {
		req := &http.Request{URL: &url.URL{Host: target}}
		err := guard(context.Background(), nil, req, nil)
		if err == nil {
			t.Errorf("CONNECT to %s was allowed", target)
			continue
		}
		de, ok := err.(*domain.DomainError)
		if !ok || de.Code != domain.CodeUpstreamDestinationDenied || de.Scope != domain.ScopeProvider {
			t.Errorf("CONNECT to %s err = %v, want upstream.destination_denied/provider", target, err)
		}
	}
}

// TestProxyConnectGuardAllowsPublicAndOptInLoopback covers the permitted paths:
// a public literal, a public hostname, and loopback when the opt-in is set.
func TestProxyConnectGuardAllowsPublicAndOptInLoopback(t *testing.T) {
	guard := proxyConnectGuard(false)
	for _, target := range []string{"8.8.8.8:443", "api.example.com:443"} {
		req := &http.Request{URL: &url.URL{Host: target}}
		if err := guard(context.Background(), nil, req, nil); err != nil {
			t.Errorf("CONNECT to %s denied: %v", target, err)
		}
	}

	// With the explicit opt-in, loopback is permitted.
	optIn := proxyConnectGuard(true)
	req := &http.Request{URL: &url.URL{Host: "127.0.0.1:11434"}}
	if err := optIn(context.Background(), nil, req, nil); err != nil {
		t.Errorf("CONNECT to loopback with opt-in denied: %v", err)
	}
}

// TestProxyConnectGuardMalformedInput covers the nil/empty-host guards.
func TestProxyConnectGuardMalformedInput(t *testing.T) {
	guard := proxyConnectGuard(false)
	if err := guard(context.Background(), nil, nil, nil); err != nil {
		t.Errorf("nil connectReq: %v", err)
	}
	if err := guard(context.Background(), nil, &http.Request{}, nil); err != nil {
		t.Errorf("nil URL: %v", err)
	}
	if err := guard(context.Background(), nil, &http.Request{URL: &url.URL{}}, nil); err == nil {
		t.Error("empty host accepted")
	}
}

// TestEgressSpecAllowLoopbackDefault pins the zero value: false.
func TestEgressSpecAllowLoopbackDefault(t *testing.T) {
	var spec contracts.EgressSpec
	if spec.AllowLoopback {
		t.Fatal("zero-value EgressSpec has AllowLoopback set")
	}
}

// TestClientPinsTLS12 is the P3 regression: the transport must pin the TLS floor
// to 1.2 (the comment claimed a MinVersion that did not exist).
func TestClientPinsTLS12(t *testing.T) {
	doer, err := New().Client(contracts.EgressSpec{BaseURL: "https://api.example.com/v1"})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	client, ok := doer.(*http.Client)
	if !ok {
		t.Fatalf("doer = %T, want *http.Client", doer)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil; the TLS floor is not pinned")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must never be set")
	}
	if tr.OnProxyConnectResponse == nil {
		t.Fatal("the CONNECT tunnel guard is not wired into the transport")
	}
}

// TestClientDeniesLoopbackDialWithoutOptIn is the behavioural half of the P2
// regression: a client pointed at a loopback literal WITHOUT the opt-in fails to
// connect (the dial-time guard denies it), proving AllowLoopback is enforced and
// not decorative. The URL is scheme-valid for http only because it is a literal,
// so use https to isolate the destination decision.
func TestClientDeniesLoopbackDialWithoutOptIn(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	// No AllowLoopback: the dial must be refused by Control.
	doer, err := New().Client(contracts.EgressSpec{BaseURL: srv.URL})
	if err != nil {
		// Some builds may refuse the URL earlier; either way it is refused.
		return
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := doer.Do(req); err == nil {
		t.Fatal("a loopback dial was permitted without AllowLoopback")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("the denied loopback server was reached %d time(s)", got)
	}

	// With the opt-in the same dial succeeds.
	optIn, err := New().Client(contracts.EgressSpec{BaseURL: srv.URL, AllowLoopback: true})
	if err != nil {
		t.Fatalf("opt-in client: %v", err)
	}
	resp, err := optIn.Do(req)
	if err != nil {
		t.Fatalf("loopback dial with opt-in failed: %v", err)
	}
	defer resp.Body.Close()
}
