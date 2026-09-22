package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// s256 mirrors RFC 7636 S256 so a test can verify the challenge independently.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// observeListen injects a listener that reports the chosen ephemeral port on a
// channel, so a test can drive the browser callback at the right address.
func observeListen(t *testing.T) (func(network, address string) (net.Listener, error), <-chan string) {
	t.Helper()
	portCh := make(chan string, 1)
	return func(network, address string) (net.Listener, error) {
		ln, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		tcp, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			_ = ln.Close()
			return nil, fmt.Errorf("listener is not TCP")
		}
		portCh <- fmt.Sprintf("%d", tcp.Port)
		return ln, nil
	}, portCh
}

// fixedClock is a deterministic Clock.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func testDeps() ClientDeps {
	return ClientDeps{
		HTTP:  &http.Client{Timeout: 5 * time.Second},
		Clock: fixedClock{t: time.Now()},
	}
}

// deviceServer simulates an RFC 8628 device authorization endpoint plus token
// endpoint. pendingCount controls how many `authorization_pending` responses
// precede success.
func deviceServer(t *testing.T, pendingCount int, withSlowDown bool) (*httptest.Server, *int64) {
	t.Helper()
	var polls int64
	mux := http.NewServeMux()

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("client_id") == "" {
			t.Error("device request carried no client_id")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "device-abc",
			"user_code":        "WXYZ-1234",
			"verification_uri": "https://example.test/activate",
			"expires_in":       300,
			"interval":         0, // forces the fast default in tests via override
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		n := atomic.AddInt64(&polls, 1)

		w.Header().Set("Content-Type", "application/json")
		// RFC 8628 §3.5: the token endpoint signals these with HTTP 400.
		if withSlowDown && n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
			return
		}
		if n <= int64(pendingCount) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type %q", r.Form.Get("grant_type"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-xyz",
			"refresh_token": "refresh-xyz",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "read write",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

// fastDeviceFlow builds a device flow whose poll interval is tiny. The flow's
// interval comes from the challenge; the test sets it directly.
func fastDeviceFlow(srv *httptest.Server) *DeviceCodeFlow {
	return NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:           "client-1",
		DeviceAuthEndpoint: srv.URL + "/device",
		TokenEndpoint:      srv.URL + "/token",
		DefaultScopes:      []string{"read", "write"},
	})
}

func TestDeviceFlowBeginAndPoll(t *testing.T) {
	srv, polls := deviceServer(t, 2, false)
	flow := fastDeviceFlow(srv)

	ch, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:           "client-1",
		DeviceAuthEndpoint: srv.URL + "/device",
		DefaultScopes:      []string{"read"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if ch.DeviceCode != "device-abc" || ch.UserCode != "WXYZ-1234" {
		t.Fatalf("challenge = %+v", ch)
	}
	if ch.VerificationURI != "https://example.test/activate" {
		t.Errorf("verification uri = %q", ch.VerificationURI)
	}
	if ch.Interval <= 0 || ch.ExpiresAt.IsZero() {
		t.Errorf("challenge missing interval/ttl: %+v", ch)
	}

	// Make the poll intervals tiny so the test runs fast.
	ch.Interval = time.Microsecond

	res, err := flow.Poll(context.Background(), ch)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.Access.Reveal() != "access-xyz" {
		t.Errorf("access = %q", res.Access.Reveal())
	}
	if res.Token.Token.Reveal() != "refresh-xyz" || !res.Token.Rotated {
		t.Errorf("refresh token = %+v", res.Token)
	}
	if res.ExpiresAt.IsZero() {
		t.Error("expires_at not set from expires_in")
	}
	if len(res.Scopes) != 2 {
		t.Errorf("scopes = %v", res.Scopes)
	}
	if atomic.LoadInt64(polls) != 3 {
		t.Errorf("polls = %d, want 3 (2 pending + 1 success)", atomic.LoadInt64(polls))
	}
}

func TestDeviceFlowSlowDownIncreasesInterval(t *testing.T) {
	srv, p := deviceServer(t, 0, true)
	flow := fastDeviceFlow(srv)
	// Keep the test fast: the production default is 5s (RFC 8628 §3.5).
	flow.SlowDownIncrement = time.Microsecond

	ch := contracts.AuthChallenge{
		DeviceCode: "device-abc",
		Interval:   time.Microsecond,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	res, err := flow.Poll(context.Background(), ch)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.Access.IsEmpty() {
		t.Error("no access token after slow_down")
	}
	if atomic.LoadInt64(p) != 2 {
		t.Errorf("polls = %d, want 2 (slow_down then success)", atomic.LoadInt64(p))
	}
}

func TestDeviceFlowAccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	}))
	defer srv.Close()

	flow := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{
		DeviceAuthEndpoint: srv.URL,
		TokenEndpoint:      srv.URL,
	})
	ch := contracts.AuthChallenge{DeviceCode: "d", Interval: time.Microsecond, ExpiresAt: time.Now().Add(time.Minute)}
	_, err := flow.Poll(context.Background(), ch)
	assertCode(t, err, domain.CodeAuthOAuthDenied)
	de := err.(*domain.DomainError)
	if de.Scope != domain.ScopeRequest || de.Retryable {
		t.Errorf("denied error must be ScopeRequest/not retryable: %+v", de)
	}
}

func TestDeviceFlowExpiredTicket(t *testing.T) {
	srv, _ := deviceServer(t, 100, false)
	flow := fastDeviceFlow(srv)

	// TTL already in the past: Poll must return oauth_flow_expired without
	// hammering the endpoint.
	ch := contracts.AuthChallenge{
		DeviceCode: "d",
		Interval:   time.Microsecond,
		ExpiresAt:  time.Now().Add(-time.Second),
	}
	_, err := flow.Poll(context.Background(), ch)
	assertCode(t, err, domain.CodeAuthFlowExpired)
}

func TestDeviceFlowContextCancellation(t *testing.T) {
	srv, _ := deviceServer(t, 1000, false)
	flow := fastDeviceFlow(srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := contracts.AuthChallenge{DeviceCode: "d", Interval: time.Hour, ExpiresAt: time.Now().Add(time.Hour)}
	_, err := flow.Poll(ctx, ch)
	if err == nil {
		t.Fatal("cancelled poll returned success")
	}
}

func TestDeviceFlowRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Errorf("refresh_token not forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access",
			"token_type":   "Bearer",
			"expires_in":   1800,
		})
	}))
	defer srv.Close()

	flow := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:      "c",
		TokenEndpoint: srv.URL,
	})
	cred := contracts.Credential{ID: "cred-1", Provider: "antigravity"}
	res, err := flow.Refresh(context.Background(), cred, contracts.RefreshToken{
		Token: contracts.Secret("old-refresh"),
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Access.Reveal() != "new-access" {
		t.Errorf("access = %q", res.Access.Reveal())
	}
	// The provider did not rotate, so the previous refresh token is preserved.
	if res.Token.Token.Reveal() != "old-refresh" || res.Token.Rotated {
		t.Errorf("refresh token = %+v, want the previous one preserved", res.Token)
	}
}

func TestDeviceFlowRefreshInvalidGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer srv.Close()

	flow := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
	_, err := flow.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{
		Token: contracts.Secret("revoked"),
	})
	assertCode(t, err, domain.CodeAuthCredentialInvalid)
	de := err.(*domain.DomainError)
	if de.Scope != domain.ScopeCredential || de.Retryable {
		t.Errorf("invalid_grant must be ScopeCredential/not retryable: %+v", de)
	}
}

// TestDeviceFlowRefreshSingleFlight models the caller-side lock: N concurrent
// refreshes with the canonical lock collapse into exactly one network call. The
// lock itself is CredentialStore.RefreshLock; here a local mutex stands in so
// the flow's idempotence under serialization is proven without the store.
func TestDeviceFlowRefreshSingleFlight(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	flow := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})

	// The lock plus a shared "already refreshed" result is the canonical
	// collapse pattern.
	var mu sync.Mutex
	var once sync.Once
	var shared contracts.AuthResult
	var refreshErr error

	doRefresh := func() error {
		mu.Lock()
		defer mu.Unlock()

		// Re-check under the lock: if a previous holder already refreshed,
		// reuse its result instead of calling the network.
		var already bool
		once.Do(func() {}) // keep once referenced; the flag below is the guard
		_ = already
		if !shared.Access.IsEmpty() {
			return refreshErr
		}

		res, err := flow.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{
			Token: contracts.Secret("r"),
		})
		shared, refreshErr = res, err
		return err
	}

	const goroutines = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := doRefresh(); err != nil {
				t.Errorf("refresh: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("network calls = %d, want exactly 1", got)
	}
}

// --- PKCE ---

func TestPKCEBeginRequiresPKCEAndState(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		TokenEndpoint:     "https://auth.example.test/token",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})

	ch, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if len(ch.State) < 22 { // 128 bits base64url is ~22 chars
		t.Errorf("state is too short: %q", ch.State)
	}
	if ch.PKCEVerifier.IsEmpty() {
		t.Error("no PKCE verifier generated")
	}
	if ch.CodeChallenge == "" {
		t.Error("no code challenge generated")
	}

	// The authorization URL must carry S256, the state and the challenge.
	u, err := url.Parse(ch.VerificationURI)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") != ch.State {
		t.Error("state not in auth URL")
	}
	if q.Get("code_challenge") != ch.CodeChallenge {
		t.Error("challenge not in auth URL")
	}
	// The verifier must NEVER appear in the URL.
	if strings.Contains(ch.VerificationURI, ch.PKCEVerifier.Reveal()) {
		t.Fatal("PKCE verifier leaked into the authorization URL")
	}
}

func TestPKCEBeginRejectsNoAllowlist(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:      "c",
		AuthEndpoint:  "https://auth.example.test/authorize",
		TokenEndpoint: "https://auth.example.test/token",
	})
	_, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:     "c",
		AuthEndpoint: "https://auth.example.test/authorize",
	})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

// TestPKCERedirectURICarriesBoundPort is the P1-1 regression guard: the
// redirect_uri advertised in the authorization URL must contain the concrete
// ephemeral port the flow is listening on, not a placeholder. Without this the
// real provider rejects the exchange and the port-ownership check of SEC-06
// does not exist.
func TestPKCERedirectURICarriesBoundPort(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		TokenEndpoint:     "https://auth.example.test/token",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = flow.Close() })

	ch, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The bound port must be present, non-zero and match the challenge.
	u, err := url.Parse(ch.RedirectURI)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	port := u.Port()
	if port == "" || port == "0" {
		t.Fatalf("redirect_uri has no concrete port: %q", ch.RedirectURI)
	}
	if u.Hostname() != "127.0.0.1" || u.Path != "/callback" {
		t.Fatalf("redirect_uri shape wrong: %q", ch.RedirectURI)
	}

	// The authorization URL must carry the SAME concrete redirect_uri.
	authURL, err := url.Parse(ch.VerificationURI)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != ch.RedirectURI {
		t.Fatalf("auth URL redirect_uri = %q, want %q", got, ch.RedirectURI)
	}

	// The advertised port is actually bound. AwaitCallback has not started the
	// HTTP server yet, so a dial (not an HTTP request) is what proves ownership
	// without blocking.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		t.Fatalf("the advertised port %s is not listening: %v", port, err)
	}
	_ = conn.Close()
}

// TestPKCERedirectTemplateMustBeLoopback rejects a redirect template that would
// send the callback off-box.
func TestPKCERedirectTemplateMustBeLoopback(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		TokenEndpoint:     "https://auth.example.test/token",
		RedirectAllowlist: []string{"http://evil.example.com/callback"},
	})
	t.Cleanup(func() { _ = flow.Close() })

	_, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		RedirectAllowlist: []string{"http://evil.example.com/callback"},
	})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

// TestPKCEEndToEndWithProvider simulates the full flow against a fake provider:
// the authorization server returns a code, the flow's listener receives the
// callback at the ADVERTISED port, and the token exchange uses the PKCE
// verifier. This is the "flow actually completes" proof for P1-1.
func TestPKCEEndToEndWithProvider(t *testing.T) {
	var (
		gotCode          string
		gotVerifier      string
		gotRedirect      string
		tokenEndpointHit bool
	)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenEndpointHit = true
		_ = r.ParseForm()
		gotCode = r.Form.Get("code")
		gotVerifier = r.Form.Get("code_verifier")
		gotRedirect = r.Form.Get("redirect_uri")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "e2e-access",
			"refresh_token": "e2e-refresh",
			"expires_in":    3600,
		})
	}))
	defer tokenSrv.Close()

	// The fake authorization server: it "authorizes" and then calls the
	// redirect_uri it was given, exactly as a browser would.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		if redirect == "" || state == "" {
			t.Error("authorization request missing redirect_uri/state")
			return
		}
		go func() {
			resp, err := http.Get(redirect + "?state=" + url.QueryEscape(state) + "&code=provider-code-1")
			if err != nil {
				t.Errorf("provider could not reach redirect_uri %q: %v", redirect, err)
				return
			}
			_ = resp.Body.Close()
		}()
		w.WriteHeader(http.StatusOK)
	}))
	defer authSrv.Close()

	desc := contracts.ProviderDescriptor{
		ID:                "fake",
		ClientID:          "client-e2e",
		AuthEndpoint:      authSrv.URL,
		TokenEndpoint:     tokenSrv.URL,
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	}
	flow := NewPKCEFlow(testDeps(), desc)
	flow.CallbackTimeout = 5 * time.Second
	t.Cleanup(func() { _ = flow.Close() })

	ch, err := flow.Begin(context.Background(), desc)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Drive the "browser": open the authorization URL.
	resp, err := http.Get(ch.VerificationURI)
	if err != nil {
		t.Fatalf("open authorization URL: %v", err)
	}
	_ = resp.Body.Close()

	res, err := flow.AwaitCallback(context.Background(), ch, desc)
	if err != nil {
		t.Fatalf("AwaitCallback: %v", err)
	}
	if res.Access.Reveal() != "e2e-access" {
		t.Errorf("access = %q", res.Access.Reveal())
	}
	if !tokenEndpointHit {
		t.Fatal("token endpoint was never called")
	}
	if gotCode != "provider-code-1" {
		t.Errorf("token exchange code = %q", gotCode)
	}
	if gotVerifier != ch.PKCEVerifier.Reveal() {
		t.Error("token exchange did not use the PKCE verifier")
	}
	if gotRedirect != ch.RedirectURI {
		t.Errorf("redirect_uri echoed = %q, want %q", gotRedirect, ch.RedirectURI)
	}
}

func TestPKCEAwaitCallbackSuccess(t *testing.T) {
	var tokenHit bool
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHit = true
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code_verifier") == "" {
			t.Error("no code_verifier sent")
		}
		if r.Form.Get("code") != "auth-code-1" {
			t.Errorf("code = %q", r.Form.Get("code"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "pkce-access",
			"refresh_token": "pkce-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenSrv.Close()

	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		TokenEndpoint:     tokenSrv.URL,
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	flow.CallbackTimeout = 5 * time.Second
	listen, portCh := observeListen(t)
	flow.Listen = listen

	desc := contracts.ProviderDescriptor{ClientID: "c", TokenEndpoint: tokenSrv.URL}
	ch, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	done := make(chan struct {
		res contracts.AuthResult
		err error
	}, 1)
	go func() {
		res, err := flow.AwaitCallback(context.Background(), ch, desc)
		done <- struct {
			res contracts.AuthResult
			err error
		}{res, err}
	}()

	port := <-portCh
	callbackURL := "http://127.0.0.1:" + port + "/callback?state=" + url.QueryEscape(ch.State) + "&code=auth-code-1"
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	_ = resp.Body.Close()

	got := <-done
	if got.err != nil {
		t.Fatalf("AwaitCallback: %v", got.err)
	}
	if got.res.Access.Reveal() != "pkce-access" {
		t.Errorf("access = %q", got.res.Access.Reveal())
	}
	if !tokenHit {
		t.Error("token endpoint never called")
	}
}

// TestPKCEAwaitCallbackStateMismatch proves a wrong state is rejected and the
// code is never exchanged.
func TestPKCEAwaitCallbackStateMismatch(t *testing.T) {
	var tokenHit bool
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHit = true
	}))
	defer tokenSrv.Close()

	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		TokenEndpoint:     tokenSrv.URL,
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	flow.CallbackTimeout = 5 * time.Second
	listen, portCh := observeListen(t)
	flow.Listen = listen

	ch, err := flow.Begin(context.Background(), contracts.ProviderDescriptor{
		ClientID:          "c",
		AuthEndpoint:      "https://auth.example.test/authorize",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := flow.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{ClientID: "c", TokenEndpoint: tokenSrv.URL})
		done <- err
	}()

	port := <-portCh
	callbackURL := "http://127.0.0.1:" + port + "/callback?state=WRONG&code=auth-code-1"
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	_ = resp.Body.Close()

	err = <-done
	assertCode(t, err, domain.CodeAuthStateMismatch)
	if tokenHit {
		t.Error("token endpoint was called despite a state mismatch")
	}
}

func TestPKCEMissingVerifierFailsClosed(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://example.test/token",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	_, err := flow.AwaitCallback(context.Background(), contracts.AuthChallenge{State: "s"}, contracts.ProviderDescriptor{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestPKCERedirectNotAllowlisted(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://example.test/token",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	_, err := flow.AwaitCallback(context.Background(), contracts.AuthChallenge{
		State:        "s",
		PKCEVerifier: contracts.Secret("v"),
		RedirectURI:  "http://evil.example.com/callback",
	}, contracts.ProviderDescriptor{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestPKCEStateIsSingleUseSize(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := NewState()
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		if len(s) < 22 {
			t.Fatalf("state too short: %d chars", len(s))
		}
		if seen[s] {
			t.Fatal("state repeated; not random")
		}
		seen[s] = true
	}
}

func TestPKCEVerifierChallengeS256(t *testing.T) {
	verifier, challenge, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("NewPKCEVerifier: %v", err)
	}
	if verifier == "" || challenge == "" || verifier == challenge {
		t.Fatalf("verifier/challenge malformed: %q / %q", verifier, challenge)
	}
	// A known S256 check: the challenge is base64url(sha256(verifier)).
	wantChallenge := s256(verifier)
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want %q", challenge, wantChallenge)
	}
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", want)
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != want {
		t.Fatalf("err = %v, want code %s", err, want)
	}
}
