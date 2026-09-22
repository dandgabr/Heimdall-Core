package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// --- deps helpers ---

func TestHTTPClientAndNowDefaults(t *testing.T) {
	var d ClientDeps
	if d.httpClient() != http.DefaultClient {
		t.Error("nil HTTP must fall back to http.DefaultClient")
	}
	custom := &http.Client{}
	d = ClientDeps{HTTP: custom}
	if d.httpClient() != custom {
		t.Error("custom HTTP client not used")
	}

	// now: Clock wins, then Now, then wall clock.
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := (ClientDeps{Clock: fixedClock{t: fixed}}).now(); !got.Equal(fixed) {
		t.Errorf("now via Clock = %v", got)
	}
	if got := (ClientDeps{Now: func() time.Time { return fixed }}).now(); !got.Equal(fixed) {
		t.Errorf("now via Now = %v", got)
	}
	if got := (ClientDeps{}).now(); got.IsZero() {
		t.Error("now with no source returned the zero time")
	}
}

func TestTokenResponseAliases(t *testing.T) {
	// camelCase aliases are used when the snake_case fields are absent.
	tr := tokenResponse{AccessTokenCamel: "a", RefreshTokenCamel: "r", ExpiresInCamel: 60}
	if tr.access() != "a" || tr.refresh() != "r" || tr.expiresIn() != 60 {
		t.Fatalf("alias fallbacks failed: %+v", tr)
	}
	// snake_case wins when both are present.
	tr2 := tokenResponse{AccessToken: "A", AccessTokenCamel: "a", ExpiresIn: 10, ExpiresInCamel: 20}
	if tr2.access() != "A" || tr2.expiresIn() != 10 {
		t.Fatalf("snake_case should win: %+v", tr2)
	}
}

// --- Kind ---

func TestFlowKinds(t *testing.T) {
	if got := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{}).Kind(); got != contracts.AuthOAuth {
		t.Errorf("device Kind = %v", got)
	}
	if got := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{}).Kind(); got != contracts.AuthOAuth {
		t.Errorf("pkce Kind = %v", got)
	}
}

// --- slowDownIncrement ---

func TestSlowDownIncrement(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{})
	if got := f.slowDownIncrement(); got != defaultSlowDownIncrement {
		t.Errorf("default increment = %v", got)
	}
	f.SlowDownIncrement = 2 * time.Second
	if got := f.slowDownIncrement(); got != 2*time.Second {
		t.Errorf("override increment = %v", got)
	}
}

// --- mapOAuthError: every branch ---

func TestMapOAuthError(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"access_denied", domain.CodeAuthOAuthDenied},
		{"expired_token", domain.CodeAuthFlowExpired},
		{"invalid_grant", domain.CodeAuthCredentialInvalid},
		{"invalid_client", domain.CodeAuthCredentialInvalid},
		{"unauthorized_client", domain.CodeAuthCredentialInvalid},
		{"insufficient_scope", domain.CodeAuthScopeInsufficient},
		{"something_else", domain.CodeAuthRefreshFailed},
	}
	for _, tt := range tests {
		err := mapOAuthError(tt.code, "desc")
		de, ok := err.(*domain.DomainError)
		if !ok || de.Code != tt.want {
			t.Errorf("mapOAuthError(%q) = %v, want %s", tt.code, err, tt.want)
		}
	}
	// The sentinels are distinct and wrapped, not returned raw.
	if !errors.Is(mapOAuthError("authorization_pending", ""), errAuthorizationPending) {
		t.Error("authorization_pending not mapped to the sentinel")
	}
	if !errors.Is(mapOAuthError("slow_down", ""), errSlowDown) {
		t.Error("slow_down not mapped to the sentinel")
	}
}

func TestNetworkErrorIsRetryableCredential(t *testing.T) {
	err := networkError(errors.New("dial refused"))
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeAuthRefreshFailed {
		t.Fatalf("networkError = %v", err)
	}
	if !de.Retryable || de.Scope != domain.ScopeCredential {
		t.Errorf("networkError must be retryable/ScopeCredential: %+v", de)
	}
}

// --- postForm error paths ---

func TestPostFormNetworkError(t *testing.T) {
	// A client whose transport always fails.
	d := ClientDeps{HTTP: &http.Client{Transport: failingTransport{}}}
	if _, err := d.postForm(context.Background(), "https://example.test/token", nil); err == nil {
		t.Fatal("transport failure accepted")
	}
}

func TestPostFormInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	if _, err := testDeps().postForm(context.Background(), srv.URL, nil); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestPostFormNon2xxWithoutErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oops"))
	}))
	defer srv.Close()

	if _, err := testDeps().postForm(context.Background(), srv.URL, nil); err == nil {
		t.Fatal("non-2xx without an OAuth error body accepted")
	}
}

func TestPostFormRequestBuildError(t *testing.T) {
	// An endpoint with a control character fails NewRequestWithContext.
	if _, err := testDeps().postForm(context.Background(), "http://exa mple.test/x", nil); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}

// --- device Begin error paths ---

func TestDeviceBeginNoEndpoint(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{})
	_, err := f.Begin(context.Background(), contracts.ProviderDescriptor{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestDeviceBeginEndpointErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"non-2xx with error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"access_denied"}`))
		}},
		{"non-2xx plain", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		}},
		{"invalid json", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{"))
		}},
		{"missing codes", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"verification_uri":"https://x"}`))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL})
			if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDeviceBeginUsesCompleteVerificationURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://x",
			"verification_uri_complete":"https://x?user_code=U","expires_in":60,"interval":1}`))
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL})
	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		DeviceAuthEndpoint: srv.URL,
		ClientID:           "c",
		DefaultScopes:      []string{"s"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if ch.VerificationURI != "https://x?user_code=U" {
		t.Errorf("verification URI = %q, want the complete form", ch.VerificationURI)
	}
	if ch.Interval != time.Second {
		t.Errorf("interval = %v", ch.Interval)
	}
}

// --- device Poll error paths ---

func TestDevicePollNoDeviceCode(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	_, err := f.Poll(context.Background(), contracts.AuthChallenge{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestDevicePollNoTokenEndpoint(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{})
	_, err := f.Poll(context.Background(), contracts.AuthChallenge{DeviceCode: "d"})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestDevicePollEmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`)) // no access_token
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
	_, err := f.Poll(context.Background(), contracts.AuthChallenge{
		DeviceCode: "d",
		Interval:   time.Microsecond,
		ExpiresAt:  time.Now().Add(time.Minute),
	})
	assertCode(t, err, domain.CodeAuthRefreshFailed)
}

func TestDevicePollSlowDownCaps(t *testing.T) {
	// Always slow_down, with a tiny increment so the loop spins quickly; the
	// interval must be capped at maxSlowDownInterval, and ctx cancellation ends
	// the loop rather than running forever.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"slow_down"}`))
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
	f.SlowDownIncrement = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := f.Poll(ctx, contracts.AuthChallenge{
		DeviceCode: "d",
		Interval:   time.Millisecond,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected cancellation to end the poll loop")
	}
	if calls == 0 {
		t.Error("token endpoint never called")
	}
}

// TestDeviceBeginDefaultTTL covers the expires_in<=0 fallback.
func TestDeviceBeginDefaultTTL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://x","expires_in":0,"interval":0}`))
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL})
	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if ch.Interval != defaultPollInterval {
		t.Errorf("interval = %v, want the default", ch.Interval)
	}
	// The TTL must be set to the default (now + 10m), i.e. well in the future.
	if time.Until(ch.ExpiresAt) < time.Minute {
		t.Errorf("expires_at = %v, want the default TTL", ch.ExpiresAt)
	}
}

// TestDevicePollDefaultInterval covers Poll's interval<=0 fallback: the
// assignment runs, then the poll is cancelled by the context.
func TestDevicePollDefaultInterval(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.Poll(ctx, contracts.AuthChallenge{DeviceCode: "d", Interval: 0, ExpiresAt: time.Now().Add(time.Hour)})
	if err == nil {
		t.Fatal("expected cancellation")
	}
}

// TestDevicePollSlowDownCap covers the interval cap branch.
func TestDevicePollSlowDownCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"slow_down"}`))
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
	// A huge increment forces the cap; the context bounds the test.
	f.SlowDownIncrement = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := f.Poll(ctx, contracts.AuthChallenge{
		DeviceCode: "d",
		Interval:   time.Millisecond,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected cancellation after the cap")
	}
}

// TestPKCEBeginListenFailure covers the listener-error branch via injection.
func TestPKCEBeginListenFailure(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	f.Listen = func(string, string) (net.Listener, error) {
		return nil, errors.New("bind refused")
	}
	_, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err == nil {
		t.Fatal("listener failure accepted")
	}
}

// --- device refresh paths ---

func TestDeviceRefreshNoEndpoint(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{})
	_, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{Token: "r"})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestDeviceRefreshNoToken(t *testing.T) {
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	_, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{})
	assertCode(t, err, domain.CodeAuthCredentialInvalid)
}

func TestDeviceRefreshEmptyAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
	_, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{
		Token: contracts.Secret("r"),
	})
	assertCode(t, err, domain.CodeAuthRefreshFailed)
}

// --- sleep ---

// TestDeviceSleepBoundedByExpiry pins sleep's contract: an already-past expiry
// shortens the wait to zero and returns nil (Poll's own loop guard raises
// oauth_flow_expired on the next iteration), while a wait that crosses the
// expiry returns the flow-expired error. Either way sleep must never outlast the
// ticket.
func TestDeviceSleepBoundedByExpiry(t *testing.T) {
	// A real clock: the sleep maths compares against deps.now(), so a frozen
	// test clock would not exercise the expiry bound.
	f := NewDeviceCodeFlow(ClientDeps{}, contracts.ProviderDescriptor{})

	// Already past: no wait at all, nil (handled by Poll).
	start := time.Now()
	if err := f.sleep(context.Background(), time.Hour, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("sleep past expiry = %v, want nil (Poll handles it)", err)
	}
	if time.Since(start) > time.Second {
		t.Error("sleep past expiry still waited")
	}

	// Zero duration with no expiry is a no-op.
	if err := f.sleep(context.Background(), 0, time.Time{}); err != nil {
		t.Errorf("zero sleep = %v", err)
	}

	// Crossing the expiry during the wait returns the typed error.
	err := f.sleep(context.Background(), 200*time.Millisecond, time.Now().Add(20*time.Millisecond))
	assertCode(t, err, domain.CodeAuthFlowExpired)
}

// --- PKCE error paths ---

func TestPKCEBeginMissingEndpoints(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	_, err := f.Begin(context.Background(), contracts.ProviderDescriptor{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

func TestPKCEBeginBadAuthURL(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	// A control character in the auth endpoint makes url.Parse fail.
	_, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint: "http://exa mple.test/auth",
	})
	if err == nil {
		t.Fatal("bad auth endpoint accepted")
	}
}

func TestPKCERedirectWithPortErrors(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		wantCode  string
	}{
		{"empty allowlist", nil, domain.CodeAuthFlowInsecure},
		{"bad url", []string{"http://[::1:bad"}, domain.CodeAuthFlowInsecure},
		{"non-loopback host", []string{"http://evil.example.com/cb"}, domain.CodeAuthFlowInsecure},
		{"bad scheme", []string{"ftp://127.0.0.1/cb"}, domain.CodeAuthFlowInsecure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{})
			if len(tt.allowlist) > 0 {
				f.allowlist = tt.allowlist
			}
			_, err := f.redirectWithPort("127.0.0.1:12345")
			assertCode(t, err, tt.wantCode)
		})
	}
}

func TestPKCEAllowedRedirectFalse(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		RedirectAllowlist: []string{"http://127.0.0.1/cb"},
	})
	if f.allowedRedirect("http://127.0.0.1/other") {
		t.Error("non-allowlisted URI accepted")
	}
	if !f.allowedRedirect("http://127.0.0.1/cb") {
		t.Error("allowlisted URI rejected")
	}
}

func TestPKCEPollIsNotInteractive(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{})
	_, err := f.Poll(context.Background(), contracts.AuthChallenge{})
	assertCode(t, err, domain.CodeAuthFlowNotInteractive)
}

func TestPKCERefreshDelegates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		_, _ = w.Write([]byte(`{"access_token":"a","expires_in":10}`))
	}))
	defer srv.Close()

	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL, ClientID: "c"})
	res, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{
		Token: contracts.Secret("r"),
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Access.Reveal() != "a" {
		t.Errorf("access = %q", res.Access.Reveal())
	}
}

func TestPKCERefreshError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	if _, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{}); err == nil {
		t.Fatal("refresh without a token accepted")
	}
}

func TestPKCEAwaitCallbackTimeout(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tokenSrv.Close()

	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     tokenSrv.URL,
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	f.CallbackTimeout = 20 * time.Millisecond
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, err = f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: tokenSrv.URL})
	assertCode(t, err, domain.CodeAuthCallbackTimeout)
}

func TestPKCEAwaitCallbackProviderError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Drive the callback with an error= parameter; the flow must map it.
	done := make(chan error, 1)
	go func() {
		_, err := f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
		done <- err
	}()
	// Reuse the flow's listener address, discovered from the challenge URI.
	port := portFromRedirect(t, ch.RedirectURI)
	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?state=" + ch.State + "&error=access_denied")
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	_ = resp.Body.Close()

	gotErr := <-done
	assertCode(t, gotErr, domain.CodeAuthOAuthDenied)
}

func TestPKCEAwaitCallbackMissingCode(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
		done <- err
	}()
	port := portFromRedirect(t, ch.RedirectURI)
	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?state=" + ch.State)
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	_ = resp.Body.Close()
	assertCode(t, <-done, domain.CodeAuthStateMismatch)
}

func TestPKCEExchangeErrorAndEmptyAccess(t *testing.T) {
	t.Run("token endpoint error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}))
		defer srv.Close()
		f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
		_, err := f.exchange(context.Background(), contracts.AuthChallenge{
			PKCEVerifier: contracts.Secret("v"), RedirectURI: "http://127.0.0.1/cb",
		}, "code", contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
		assertCode(t, err, domain.CodeAuthCredentialInvalid)
	})

	t.Run("empty access token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		}))
		defer srv.Close()
		f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
		_, err := f.exchange(context.Background(), contracts.AuthChallenge{
			PKCEVerifier: contracts.Secret("v"), RedirectURI: "http://127.0.0.1/cb",
		}, "code", contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
		assertCode(t, err, domain.CodeAuthRefreshFailed)
	})
}

func TestPKCEAwaitCallbackAfterCloseFailsClosed(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	// No Begin: no listener bound.
	_, err := f.AwaitCallback(context.Background(), contracts.AuthChallenge{
		State:        "s",
		PKCEVerifier: contracts.Secret("v"),
		RedirectURI:  "http://127.0.0.1:1/callback",
	}, contracts.ProviderDescriptor{})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

// --- helpers ---

// TestNewStateEntropyError covers NewState's crypto/rand error branch.
func TestNewStateEntropyError(t *testing.T) {
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	if _, err := NewState(); err == nil {
		t.Fatal("NewState succeeded without entropy")
	}
	randReader = old
}

// TestNewPKCEVerifierEntropyError covers NewPKCEVerifier's error branch.
func TestNewPKCEVerifierEntropyError(t *testing.T) {
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	if _, _, err := NewPKCEVerifier(); err == nil {
		t.Fatal("NewPKCEVerifier succeeded without entropy")
	}
	randReader = old
}

// failingReader always fails, so the crypto/rand error branch is reachable.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial refused")
}

func portFromRedirect(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", raw, err)
	}
	return u.Port()
}

// TestPKCEBeginWithScopes covers the scope-setting branch.
func TestPKCEBeginWithScopes(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = f.Close() })
	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
		DefaultScopes:     []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(ch.VerificationURI)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := u.Query().Get("scope"); got != "read write" {
		t.Errorf("scope = %q, want %q", got, "read write")
	}
}

// TestPKCERedirectWithPortBadBoundAddr covers the SplitHostPort-error branch.
func TestPKCERedirectWithPortBadBoundAddr(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if _, err := f.redirectWithPort("no-port-here"); err == nil {
		t.Fatal("bound address without a port accepted")
	}
}

// TestPKCEAwaitCallbackChallengeMismatch covers the branch where the challenge's
// redirect URI does not match the bound listener.
func TestPKCEAwaitCallbackChallengeMismatch(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	ch.RedirectURI = "http://127.0.0.1:1/callback"
	_, err = f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

// TestPKCEBeginEntropyError covers Begin's NewState-failure branch.
func TestPKCEBeginEntropyError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	}); err == nil {
		t.Fatal("Begin succeeded without entropy")
	}
	randReader = old
}

// TestOAuthPostFormReadError covers postForm's body-read error via a response
// whose Body fails to read.
func TestOAuthPostFormReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()
	if _, err := testDeps().postForm(context.Background(), srv.URL, nil); err == nil {
		t.Fatal("postForm accepted a truncated body")
	}
}

// TestDeviceBeginNetworkAndBuildErrors covers Begin's request-build, Do, and
// body-read error branches.
func TestDeviceBeginNetworkAndBuildErrors(t *testing.T) {
	// Request-build error: a control character in the endpoint.
	fBad := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{DeviceAuthEndpoint: "http://exa mple.test/device"})
	if _, err := fBad.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: "http://exa mple.test/device"}); err == nil {
		t.Error("Begin accepted a control character in the endpoint")
	}

	// Do error: a failing transport.
	deps := testDeps()
	deps.HTTP = &http.Client{Transport: failingTransport{}}
	fNet := NewDeviceCodeFlow(deps, contracts.ProviderDescriptor{DeviceAuthEndpoint: "https://example.test/device"})
	if _, err := fNet.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: "https://example.test/device"}); err == nil {
		t.Error("Begin succeeded with a failing transport")
	}
}

// TestDeviceBeginBodyReadError covers Begin's io.ReadAll error.
func TestDeviceBeginBodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()
	f := NewDeviceCodeFlow(testDeps(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL})
	if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{DeviceAuthEndpoint: srv.URL}); err == nil {
		t.Fatal("Begin accepted a truncated body")
	}
}

// TestPKCEBeginVerifierEntropyError covers the NewPKCEVerifier-failure branch:
// the state call succeeds, the verifier call fails.
func TestPKCEBeginVerifierEntropyError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	old := randReader
	randReader = &partialReader{remaining: 32} // state reads 32 bytes, verifier then fails
	t.Cleanup(func() { randReader = old })
	if _, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	}); err == nil {
		t.Fatal("Begin succeeded when the verifier read failed")
	}
	randReader = old
}

// TestPKCEAwaitCallbackExchangeError covers AwaitCallback's exchange error
// branch: the callback succeeds but the token endpoint rejects the code.
func TestPKCEAwaitCallbackExchangeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     srv.URL,
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	f.CallbackTimeout = 5 * time.Second
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: srv.URL})
		done <- err
	}()
	port := portFromRedirect(t, ch.RedirectURI)
	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?state=" + ch.State + "&code=c")
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	_ = resp.Body.Close()
	assertCode(t, <-done, domain.CodeAuthCredentialInvalid)
}

// TestPKCERefreshWithTokenEndpointError covers PKCE Refresh's postForm error.
func TestPKCERefreshWithTokenEndpointError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{TokenEndpoint: "http://exa mple.test/token"})
	if _, err := f.Refresh(context.Background(), contracts.Credential{}, contracts.RefreshToken{Token: contracts.Secret("r")}); err == nil {
		t.Fatal("Refresh accepted an invalid token endpoint")
	}
}

// partialReader returns n bytes then fails, so a two-read sequence can have the
// first succeed and the second fail.
type partialReader struct{ remaining int }

func (p *partialReader) Read(b []byte) (int, error) {
	if p.remaining <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	n := len(b)
	if n > p.remaining {
		n = p.remaining
	}
	for i := 0; i < n; i++ {
		b[i] = 0x7a
	}
	p.remaining -= n
	return n, nil
}

// TestPKCEAwaitCallbackContextCancel covers AwaitCallback's ctx.Done branch:
// the caller cancels while waiting for the callback.
func TestPKCEAwaitCallbackContextCancel(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	f.CallbackTimeout = 5 * time.Second
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.AwaitCallback(ctx, ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AwaitCallback returned nil after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AwaitCallback did not return after cancellation")
	}
}

// TestPKCEAwaitCallbackRedirectError covers AwaitCallback's redirectWithPort
// error branch: the allowlist is emptied AFTER Begin, so the re-derivation in
// AwaitCallback fails.
func TestPKCEAwaitCallbackRedirectError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Empty the allowlist so redirectWithPort (called inside AwaitCallback)
	// fails with "no redirect allowlist configured".
	f.allowlist = nil
	_, err = f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	assertCode(t, err, domain.CodeAuthFlowInsecure)
}

// TestPKCEAwaitCallbackServeError covers the serveErr branch: the listener is
// closed before Serve starts, so Serve returns a non-ErrServerClosed error and
// the select takes the serveErr case.
func TestPKCEAwaitCallbackServeError(t *testing.T) {
	f := NewPKCEFlow(testDeps(), contracts.ProviderDescriptor{
		TokenEndpoint:     "https://x",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	f.CallbackTimeout = 2 * time.Second
	t.Cleanup(func() { _ = f.Close() })

	ch, err := f.Begin(context.Background(), contracts.ProviderDescriptor{
		AuthEndpoint:      "https://example.test/auth",
		RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Close the listener Begin bound, so srv.Serve fails immediately.
	if f.listener != nil {
		_ = f.listener.Close()
	}
	_, err = f.AwaitCallback(context.Background(), ch, contracts.ProviderDescriptor{TokenEndpoint: "https://x"})
	if err == nil {
		t.Fatal("AwaitCallback succeeded after the listener was closed")
	}
}
