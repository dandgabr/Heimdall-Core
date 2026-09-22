package egress

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// --- ValidateUpstreamURL ---

func TestValidateUpstreamURL(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantLoopback bool
		wantErr      bool
	}{
		{"https public", "https://api.example.com/v1", false, false},
		{"https loopback", "https://127.0.0.1/v1", true, false},
		{"https ipv6 loopback", "https://[::1]/v1", true, false},
		{"http loopback literal", "http://127.0.0.1:11434/v1", true, false},
		{"http non-loopback rejected", "http://api.example.com/v1", false, true},
		{"http localhost name rejected", "http://localhost/v1", false, true},
		{"no scheme", "api.example.com", false, true},
		{"ftp rejected", "ftp://example.com", false, true},
		{"no host", "http://", false, true},
		{"unparseable", "://bad", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loop, err := ValidateUpstreamURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tt.raw)
				}
				de, ok := err.(*domain.DomainError)
				if !ok || de.Code != domain.CodeUpstreamInsecureURL {
					t.Fatalf("err = %v, want %s", err, domain.CodeUpstreamInsecureURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if loop != tt.wantLoopback {
				t.Errorf("loopback = %v, want %v", loop, tt.wantLoopback)
			}
		})
	}
}

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

// --- DeniedIP / SSRFControl ---

// TestDeniedIPRange is the ADR-SEC-05 §3 acceptance table: every denied range
// plus the explicit-loopback exception and the IPv4-mapped collapse.
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
		{"fd00:ec2::254", false, true},          // AWS IMDSv6
		{"100.100.100.200", false, true},        // Alibaba metadata
		{"fe80::1", false, true},                // link-local
		{"ff02::1", false, true},                // link-local multicast
		{"224.0.0.1", false, true},              // multicast
		{"255.255.255.255", false, true},        // broadcast
		{"0.0.0.0", false, true},                // unspecified
		{"::", false, true},                     // unspecified v6
		{"fc00::1", false, true},                // ULA
		{"ff01::1", false, true},                // interface-local multicast
		{"93.184.216.34", false, false},         // public
		{"8.8.8.8", false, false},
	}
	for _, tt := range tests {
		addr, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.ip, err)
		}
		if got := DeniedIP(addr, tt.allowLoopback); got != tt.wantDenied {
			t.Errorf("DeniedIP(%s, allow=%v) = %v, want %v", tt.ip, tt.allowLoopback, got, tt.wantDenied)
		}
	}
	if !DeniedIP(netip.Addr{}, false) {
		t.Error("invalid IP was not denied")
	}
}

func TestSSRFControlDeniesPrivateDestinations(t *testing.T) {
	allow := func(address string) error { return SSRFControl(false)("tcp", address, nil) }

	tests := map[string]bool{
		"127.0.0.1:80":                true,
		"169.254.169.254:80":          true,
		"10.0.0.5:80":                 true,
		"192.168.1.10:80":             true,
		"172.16.5.4:80":               true,
		"[::1]:80":                    true,
		"[fe80::1]:80":                true,
		"[::ffff:169.254.169.254]:80": true,
		"93.184.216.34:80":            false,
		"8.8.8.8:53":                  false,
	}
	for addr, wantDenied := range tests {
		err := allow(addr)
		if wantDenied && err == nil {
			t.Errorf("%s: expected denial", addr)
		}
		if !wantDenied && err != nil {
			t.Errorf("%s: unexpected denial: %v", addr, err)
		}
	}
}

func TestSSRFControlAllowsExplicitLoopback(t *testing.T) {
	if err := SSRFControl(true)("tcp", "127.0.0.1:11434", nil); err != nil {
		t.Errorf("loopback should be allowed for a loopback upstream: %v", err)
	}
}

func TestSSRFControlNonLiteralHostFailsClosed(t *testing.T) {
	err := SSRFControl(false)("tcp", "example.com:80", nil)
	if err == nil {
		t.Fatal("non-literal host accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamDestinationDenied {
		t.Fatalf("err = %v, want upstream.destination_denied", err)
	}
	if de.Scope != domain.ScopeProvider {
		t.Errorf("scope = %v, want ScopeProvider", de.Scope)
	}
}

func TestSSRFControlAddressWithoutPort(t *testing.T) {
	if err := SSRFControl(false)("tcp", "8.8.8.8", nil); err != nil {
		t.Errorf("bare public IP rejected: %v", err)
	}
}

// --- Policy.Client ---

func TestPolicyClientBuildsValidClient(t *testing.T) {
	p := New()
	doer, err := p.Client(contracts.EgressSpec{BaseURL: "https://api.example.com/v1"})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if doer == nil {
		t.Fatal("nil client")
	}

	// A loopback HTTP upstream is allowed only through the explicit flag.
	if _, err := p.Client(contracts.EgressSpec{BaseURL: "http://127.0.0.1:11434/v1", AllowLoopback: true}); err != nil {
		t.Fatalf("loopback client: %v", err)
	}
}

func TestPolicyClientRejectsInvalidSpec(t *testing.T) {
	if _, err := New().Client(contracts.EgressSpec{}); err == nil {
		t.Fatal("empty spec accepted")
	}
}

// --- proxy validation ---

func TestValidatedProxySchemes(t *testing.T) {
	p := New()
	tests := map[string]bool{
		"http://proxy:8080":        true,
		"https://proxy:8080":       true,
		"socks5://proxy:1080":      true,
		"ftp://proxy:21":           false,
		"http://user:pass@proxy:8": true, // credentials are allowed but never logged
	}
	for raw, wantOK := range tests {
		t.Run(raw, func(t *testing.T) {
			u, _ := url.Parse(raw)
			p.proxyFromEnv = func(*http.Request) (*url.URL, error) { return u, nil }
			_, err := p.validatedProxy(nil)
			if wantOK && err != nil {
				t.Fatalf("scheme rejected: %v", err)
			}
			if !wantOK {
				if err == nil {
					t.Fatal("bad scheme accepted")
				}
				de, ok := err.(*domain.DomainError)
				if !ok || de.Code != domain.CodeUpstreamInsecureURL {
					t.Fatalf("err = %v, want upstream.insecure_url", err)
				}
				// The credential must never appear in the error.
				if de.Params["url"] != "" && containsStr(de.Params["url"], "pass") {
					t.Fatalf("proxy credential leaked: %q", de.Params["url"])
				}
			}
		})
	}
}

func TestValidatedProxyNilAndError(t *testing.T) {
	p := New()
	p.proxyFromEnv = func(*http.Request) (*url.URL, error) { return nil, nil }
	if got, err := p.validatedProxy(nil); got != nil || err != nil {
		t.Fatalf("nil proxy = %v, %v", got, err)
	}
}

func containsStr(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// --- redirect policy ---

func TestRedirectPolicyRefusesByDefault(t *testing.T) {
	rp := redirectPolicy(contracts.EgressSpec{FollowRedirects: false})
	if err := rp(nil, nil); err == nil {
		t.Fatal("default redirect policy allowed a redirect")
	}
}

func TestRedirectPolicyCapsAndRevalidates(t *testing.T) {
	rp := redirectPolicy(contracts.EgressSpec{FollowRedirects: true, MaxRedirects: 2})
	// Within the cap and a valid target: allowed.
	req := &http.Request{URL: mustURL(t, "https://api.example.com/next")}
	if err := rp(req, make([]*http.Request, 1)); err != nil {
		t.Fatalf("valid hop rejected: %v", err)
	}
	// Over the cap.
	if err := rp(req, make([]*http.Request, 2)); err == nil {
		t.Fatal("cap not enforced")
	}
	// A hop to an insecure URL is rejected.
	bad := &http.Request{URL: mustURL(t, "http://evil.example.com/")}
	if err := rp(bad, nil); err == nil {
		t.Fatal("insecure redirect target accepted")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestClientDoesNotFollowRedirectToLoopback is the ADR-SEC-05 §4 acceptance test:
// an upstream answering 302 to a loopback/metadata address must not be followed.
func TestClientDoesNotFollowRedirectToLoopback(t *testing.T) {
	var targetHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte("should not be reached"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// The redirector is a loopback literal, so allow it explicitly; the point is
	// that the FOLLOWED hop (also loopback) is never taken.
	doer, err := New().Client(contracts.EgressSpec{
		BaseURL:       redirector.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	resp, err := doer.Do(mustRequest(t, redirector.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (not followed)", resp.StatusCode)
	}
	if targetHit {
		t.Fatal("redirect to loopback was followed")
	}
}

// TestClientRejectsPlainHTTPRemote is the ADR-SEC-05 §2 acceptance test.
func TestClientRejectsPlainHTTPRemote(t *testing.T) {
	_, err := New().Client(contracts.EgressSpec{BaseURL: "http://api.example.com/v1"})
	if err == nil {
		t.Fatal("plain HTTP remote accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamInsecureURL {
		t.Fatalf("err = %v, want upstream.insecure_url", err)
	}
}

func mustRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
