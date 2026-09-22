package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
)

// egressDeps builds deps whose client comes from the REAL ADR-SEC-05 egress
// policy, with the loopback exception unlocked for the httptest server. This is
// what proves OAuth goes through the policy (CheckRedirect + SSRFControl).
func egressDeps(allowLoopback bool) ClientDeps {
	return ClientDeps{
		Egress:        egress.New(),
		AllowLoopback: allowLoopback,
		Clock:         fixedClock{t: time.Now()},
	}
}

// attackerServer records whether it ever received an Authorization header.
type attackerServer struct {
	srv  *httptest.Server
	hits int32
	auth int32
}

func newAttackerServer(t *testing.T) *attackerServer {
	t.Helper()
	a := &attackerServer{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&a.hits, 1)
		if r.Header.Get("Authorization") != "" {
			atomic.AddInt32(&a.auth, 1)
		}
		_, _ = w.Write([]byte(`{"access_token":"LEAKED"}`))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// TestOAuthTokenExchangeBlocksRedirect is the P0 regression: a token endpoint
// that answers 302 to an attacker must NOT cause the Authorization header to be
// forwarded. The egress policy returns http.ErrUseLastResponse, so the redirect
// is never followed.
func TestOAuthTokenExchangeBlocksRedirect(t *testing.T) {
	attacker := newAttackerServer(t)
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.srv.URL+"/steal", http.StatusFound)
	}))
	defer victim.Close()

	deps := egressDeps(true)
	_, err := deps.postForm(context.Background(), victim.URL+"/token", url.Values{"grant_type": {"authorization_code"}})
	if err == nil {
		t.Fatal("redirect to the attacker was not rejected")
	}
	if hits := atomic.LoadInt32(&attacker.hits); hits != 0 {
		t.Fatalf("attacker was contacted %d time(s); the redirect was followed", hits)
	}
	if auth := atomic.LoadInt32(&attacker.auth); auth != 0 {
		t.Fatalf("attacker received the Authorization header %d time(s)", auth)
	}
}

// TestOAuthUserInfoBlocksRedirect is the same regression on the Antigravity
// post-exchange userinfo call, which carries the access token as a Bearer.
func TestOAuthUserInfoBlocksRedirect(t *testing.T) {
	attacker := newAttackerServer(t)
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("victim did not receive the bearer token it forwards")
		}
		http.Redirect(w, r, attacker.srv.URL+"/steal", http.StatusFound)
	}))
	defer victim.Close()

	desc := contracts.ProviderDescriptor{TokenEndpoint: victim.URL}
	flow := NewAntigravityFlow(egressDeps(true), desc, AntigravityConfig{UserInfoEndpoint: victim.URL + "/userinfo"})
	if _, err := flow.fetchUserInfo(context.Background(), "access-token"); err == nil {
		t.Fatal("redirect from userinfo was not rejected")
	}
	if hits := atomic.LoadInt32(&attacker.hits); hits != 0 {
		t.Fatalf("attacker was contacted %d time(s) via userinfo", hits)
	}
	if auth := atomic.LoadInt32(&attacker.auth); auth != 0 {
		t.Fatalf("attacker received the bearer token %d time(s)", auth)
	}
}

// TestOAuthDenylistBlocksLoopback proves the OAuth client carries the SSRF
// dial-time denylist: with AllowLoopback false, a loopback token endpoint is
// denied at dial time with error.upstream_destination_denied.
func TestOAuthDenylistBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("denied loopback server was reached")
	}))
	defer srv.Close()

	deps := egressDeps(false) // loopback NOT unlocked
	_, err := deps.postForm(context.Background(), srv.URL+"/token", url.Values{})
	if err == nil {
		t.Fatal("loopback token endpoint was permitted without the opt-in")
	}
	// The typed denial must survive the flow's error mapping.
	de := asDomainError(err)
	if de == nil || de.Code != domain.CodeUpstreamDestinationDenied {
		t.Fatalf("err = %v, want %s", err, domain.CodeUpstreamDestinationDenied)
	}
}

// TestOAuthDeviceBeginBlocksRedirect covers the device-authorization Begin call.
func TestOAuthDeviceBeginBlocksRedirect(t *testing.T) {
	attacker := newAttackerServer(t)
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.srv.URL+"/steal", http.StatusFound)
	}))
	defer victim.Close()

	f := NewDeviceCodeFlow(egressDeps(true), contracts.ProviderDescriptor{DeviceAuthEndpoint: victim.URL})
	if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: victim.URL}); err == nil {
		t.Fatal("device Begin followed a redirect")
	}
	if atomic.LoadInt32(&attacker.hits) != 0 {
		t.Fatal("attacker contacted via device Begin")
	}
}

// TestOAuthNoPolicyFailsClosed proves a flow with neither a test client nor an
// egress policy refuses rather than silently using http.DefaultClient.
func TestOAuthNoPolicyFailsClosed(t *testing.T) {
	deps := ClientDeps{Clock: fixedClock{t: time.Now()}}
	if _, err := deps.postForm(context.Background(), "https://example.test/token", url.Values{}); err == nil {
		t.Fatal("postForm with no transport did not fail closed")
	} else if de := asDomainError(err); de == nil || de.Code != domain.CodeAuthFlowInsecure {
		t.Fatalf("err = %v, want auth.flow_insecure", err)
	}

	// fetchUserInfo and the discovery POSTs must also fail closed.
	flow := NewAntigravityFlow(deps, contracts.ProviderDescriptor{}, AntigravityConfig{
		UserInfoEndpoint: "https://example.test/u", LoadCodeAssistEndpoint: "https://example.test/lca",
		OnboardUserEndpoint: "https://example.test/onb", OnboardAttempts: 1,
	})
	if _, err := flow.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("fetchUserInfo with no transport did not fail closed")
	}
	if _, ok := flow.postJSON(context.Background(), "https://example.test/lca", "t", []byte(`{}`)); ok {
		t.Fatal("postJSON with no transport did not fail closed")
	}
}

// asDomainError unwraps a *domain.DomainError through the flow helpers.
func asDomainError(err error) *domain.DomainError {
	de, _ := err.(*domain.DomainError)
	return de
}

// TestOAuthPolicyClientIsUsed proves the policy path builds a real *http.Client
// whose CheckRedirect refuses redirects (the concrete mechanism behind the
// regression tests above).
func TestOAuthPolicyClientIsUsed(t *testing.T) {
	doer, err := egressDeps(true).doerFor("https://example.test/token")
	if err != nil {
		t.Fatalf("doerFor: %v", err)
	}
	client, ok := doer.(*http.Client)
	if !ok {
		t.Fatalf("doer = %T, want *http.Client (policy-bound)", doer)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
	err = client.CheckRedirect(req, nil)
	if err == nil {
		t.Fatal("policy client followed a redirect")
	}
	if err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect err = %v, want ErrUseLastResponse", err)
	}
}

// TestEgressPolicyErrorNonPolicyCode covers the default branch: a typed domain
// error that is NOT a policy refusal must not be treated as one.
func TestEgressPolicyErrorNonPolicyCode(t *testing.T) {
	other := domain.New(domain.CodeBadUpstreamResponse, domain.WithHTTPStatus(400))
	if got := egressPolicyError(other); got != nil {
		t.Fatalf("egressPolicyError(other) = %+v, want nil", got)
	}
	if got := egressPolicyError(context.Canceled); got != nil {
		t.Fatalf("egressPolicyError(non-domain) = %+v, want nil", got)
	}
}

// TestDeviceBeginNoPolicyFailsClosed covers Begin's doerFor error branch.
func TestDeviceBeginNoPolicyFailsClosed(t *testing.T) {
	f := NewDeviceCodeFlow(ClientDeps{Clock: fixedClock{t: time.Now()}}, contracts.ProviderDescriptor{DeviceAuthEndpoint: "https://example.test/device"})
	_, err := f.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: "https://example.test/device"})
	if err == nil {
		t.Fatal("device Begin with no transport did not fail closed")
	}
	if de := asDomainError(err); de == nil || de.Code != domain.CodeAuthFlowInsecure {
		t.Fatalf("err = %v, want auth.flow_insecure", err)
	}
}

// TestOnboardNoPolicyDoesNotStart covers the doerFor-error guard: with no
// transport configured the onboarding is simply not started (no panic, no
// block).
func TestOnboardNoPolicyDoesNotStart(t *testing.T) {
	flow := NewAntigravityFlow(ClientDeps{Clock: fixedClock{t: time.Now()}}, antigravityDesc(), AntigravityConfig{
		OnboardUserEndpoint: "https://example.test/onboard", OnboardAttempts: 1,
	})
	flow.onboardUserAsync(context.Background(), "t", "tier") // must return immediately
}
