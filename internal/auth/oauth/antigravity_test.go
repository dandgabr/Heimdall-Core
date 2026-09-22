package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// antigravityDesc is a descriptor requiring the client secret.
func antigravityDesc() contracts.ProviderDescriptor {
	return contracts.ProviderDescriptor{
		ClientID:             "client-id",
		ClientSecret:         "client-secret",
		RequiresClientSecret: true,
		AuthEndpoint:         "https://accounts.google.com/o/oauth2/v2/auth",
		TokenEndpoint:        "https://oauth2.googleapis.com/token",
		DefaultScopes:        []string{"https://www.googleapis.com/auth/cloud-platform"},
		RedirectAllowlist:    []string{"http://127.0.0.1/callback"},
	}
}

// TestPKCEBeginAddsOfflineConsent proves the confidential-client Begin URL carries
// access_type=offline and prompt=consent (needed to obtain a refresh token).
func TestPKCEBeginAddsOfflineConsent(t *testing.T) {
	flow := NewPKCEFlow(testDeps(), antigravityDesc())
	listen, _ := observeListen(t)
	flow.Listen = listen
	ch, err := flow.Begin(context.Background(), antigravityDesc())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer flow.Close()
	u, err := url.Parse(ch.VerificationURI)
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	q := u.Query()
	if q.Get("access_type") != "offline" || q.Get("prompt") != "consent" {
		t.Fatalf("missing offline/consent: %s", ch.VerificationURI)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Error("PKCE S256 missing")
	}
}

// TestPKCEClientSecretFlow proves the exchange sends client_secret when the
// descriptor requires it, and omits it otherwise.
func TestPKCEClientSecretFlow(t *testing.T) {
	run := func(t *testing.T, requires bool) url.Values {
		t.Helper()
		var last url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			last = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "expires_in": 3600})
		}))
		defer srv.Close()

		desc := contracts.ProviderDescriptor{TokenEndpoint: srv.URL, ClientID: "cid", ClientSecret: "SEC", RequiresClientSecret: requires}
		flow := NewPKCEFlow(testDeps(), desc)
		_, err := flow.exchange(context.Background(),
			contracts.AuthChallenge{PKCEVerifier: contracts.Secret("verifier"), RedirectURI: "http://127.0.0.1/callback"},
			"code-1", desc)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if last == nil {
			t.Fatal("token endpoint not called")
		}
		return last
	}

	if got := run(t, true).Get("client_secret"); got != "SEC" {
		t.Fatalf("client_secret = %q, want SEC", got)
	}
	if got := run(t, false).Get("client_secret"); got != "" {
		t.Fatalf("client_secret = %q, want empty", got)
	}
}

// TestAntigravityPostExchange proves the post-exchange fills email/project/tier
// and never blocks on onboarding.
func TestAntigravityPostExchange(t *testing.T) {
	var onboarded int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "userinfo"):
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Error("userinfo carried no bearer token")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sub-1", "email": "u@example.com"})
		case strings.Contains(r.URL.Path, "loadCodeAssist"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cloudaicompanionProject": map[string]any{"id": "proj-xyz"},
				"allowedTiers":            []map[string]any{{"id": "free-tier", "isDefault": true}},
			})
		case strings.Contains(r.URL.Path, "onboardUser"):
			atomic.AddInt32(&onboarded, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := AntigravityConfig{
		UserInfoEndpoint:       srv.URL + "/userinfo",
		LoadCodeAssistEndpoint: srv.URL + "/loadCodeAssist",
		OnboardUserEndpoint:    srv.URL + "/onboardUser",
		UserAgent:              "antigravity/ide/2.11.0 darwin/arm64",
		Metadata:               AntigravityClientMetadata{IDEType: 9, Platform: 2, PluginType: 2},
		OnboardAttempts:        1,
	}
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), cfg)

	// Drive the post-exchange deterministically (the grant itself is covered by
	// the PKCE tests). The onboarder is replaced with a synchronous call.
	var onboardSeen string
	flow.onboard = func(_ context.Context, token, tier string) {
		onboardSeen = tier
		req, _ := http.NewRequest(http.MethodPost, cfg.OnboardUserEndpoint, strings.NewReader(`{"tierId":"free-tier"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		doer, _ := testDeps().doerFor(cfg.OnboardUserEndpoint)
		resp, err := doer.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}

	res, err := flow.postExchange(context.Background(), contracts.AuthResult{Access: contracts.Secret("access-tok"), AuthMode: contracts.AuthOAuth})
	if err != nil {
		t.Fatalf("postExchange: %v", err)
	}
	if res.Account.Email != "u@example.com" || res.Account.Subject != "sub-1" {
		t.Errorf("account = %+v", res.Account)
	}
	if res.Account.Project != "proj-xyz" {
		t.Errorf("project = %q, want proj-xyz", res.Account.Project)
	}
	if res.Account.Plan != "free-tier" {
		t.Errorf("plan = %q, want free-tier", res.Account.Plan)
	}
	if onboardSeen != "free-tier" {
		t.Errorf("onboard saw tier %q", onboardSeen)
	}
	if atomic.LoadInt32(&onboarded) != 1 {
		t.Errorf("onboardUser called %d times, want 1", onboarded)
	}
}

// TestAntigravityPostExchangeBestEffort proves a discovery failure does not fail
// the grant: the project falls back to the default tier, no project.
func TestAntigravityPostExchangeBestEffort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500) // every discovery call fails
	}))
	defer srv.Close()

	cfg := AntigravityConfig{
		UserInfoEndpoint:       srv.URL + "/userinfo",
		LoadCodeAssistEndpoint: srv.URL + "/loadCodeAssist",
		OnboardUserEndpoint:    srv.URL + "/onboardUser",
		OnboardAttempts:        1,
	}
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), cfg)
	flow.onboard = func(context.Context, string, string) { t.Error("onboard ran without a project") }

	res, err := flow.postExchange(context.Background(), contracts.AuthResult{Access: contracts.Secret("tok")})
	if err != nil {
		t.Fatalf("postExchange should be best-effort: %v", err)
	}
	if res.Account.Project != "" {
		t.Errorf("project = %q, want empty", res.Account.Project)
	}
	if res.Account.Plan != defaultLegacyTier {
		t.Errorf("plan = %q, want %q", res.Account.Plan, defaultLegacyTier)
	}
}

// TestAntigravityProjectAsBareString covers the string shape of
// cloudaicompanionProject.
func TestAntigravityProjectAsBareString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "loadCodeAssist") {
			_ = json.NewEncoder(w).Encode(map[string]any{"cloudaicompanionProject": "bare-proj"})
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	cfg := AntigravityConfig{LoadCodeAssistEndpoint: srv.URL + "/loadCodeAssist", OnboardAttempts: 1}
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), cfg)
	project, tier := flow.loadCodeAssist(context.Background(), "tok")
	if project != "bare-proj" {
		t.Errorf("project = %q, want bare-proj", project)
	}
	if tier != defaultLegacyTier {
		t.Errorf("tier = %q, want %q", tier, defaultLegacyTier)
	}
}

// TestAntigravityOnboardAsyncFireAndForget proves the async onboarder actually
// runs: the handler signals a channel, and the test WAITS on it (no bare sleep)
// and asserts the request arrived with the tier.
func TestAntigravityOnboardAsyncFireAndForget(t *testing.T) {
	type seen struct {
		tier string
		auth string
	}
	got := make(chan seen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			TierID string `json:"tierId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- seen{tier: body.TierID, auth: r.Header.Get("Authorization")}
		_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
	}))
	defer srv.Close()
	cfg := AntigravityConfig{
		OnboardUserEndpoint: srv.URL, UserAgent: "ua",
		Metadata: AntigravityClientMetadata{IDEType: 9}, OnboardAttempts: 1,
	}
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), cfg)
	flow.onboardUserAsync(context.Background(), "tok", "tier-42")

	select {
	case s := <-got:
		if s.tier != "tier-42" {
			t.Errorf("onboard tier = %q, want tier-42", s.tier)
		}
		if s.auth != "Bearer tok" {
			t.Errorf("onboard Authorization = %q, want the bearer token", s.auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the async onboarder never called the endpoint")
	}
}

// TestAntigravityFlowKindAndContract pins Kind and the contract.
func TestAntigravityFlowKindAndContract(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), DefaultAntigravityConfig())
	if flow.Kind() != contracts.AuthOAuth {
		t.Fatalf("Kind = %v", flow.Kind())
	}
	var _ contracts.AuthFlow = flow
}

// TestAntigravityDefaultConfig pins the production endpoints and metadata.
func TestAntigravityDefaultConfig(t *testing.T) {
	cfg := DefaultAntigravityConfig()
	if !strings.Contains(cfg.UserInfoEndpoint, "userinfo") {
		t.Errorf("userinfo endpoint = %q", cfg.UserInfoEndpoint)
	}
	if !strings.Contains(cfg.LoadCodeAssistEndpoint, "v1internal:loadCodeAssist") {
		t.Errorf("loadCodeAssist endpoint = %q", cfg.LoadCodeAssistEndpoint)
	}
	if !strings.Contains(cfg.OnboardUserEndpoint, "v1internal:onboardUser") {
		t.Errorf("onboardUser endpoint = %q", cfg.OnboardUserEndpoint)
	}
	if cfg.Metadata.IDEType != 9 || cfg.Metadata.PluginType != 2 {
		t.Errorf("metadata = %+v", cfg.Metadata)
	}
}

// TestPostExchangeNoTokenIsNoop covers the empty-token guard.
func TestPostExchangeNoTokenIsNoop(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{})
	res, err := flow.postExchange(context.Background(), contracts.AuthResult{})
	if err != nil || res.Access.Reveal() != "" {
		t.Fatalf("no-op postExchange = %+v, %v", res, err)
	}
}

// TestPostExchangeFetchUserInfoError covers the userinfo failure branch (project
// discovery still runs).
func TestPostExchangeFetchUserInfoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "userinfo") {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"cloudaicompanionProject": "p"})
	}))
	defer srv.Close()
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{
		UserInfoEndpoint: srv.URL + "/userinfo", LoadCodeAssistEndpoint: srv.URL + "/lca", OnboardAttempts: 1,
	})
	flow.onboard = func(context.Context, string, string) {}
	res, err := flow.postExchange(context.Background(), contracts.AuthResult{Access: contracts.Secret("t")})
	if err != nil {
		t.Fatalf("postExchange: %v", err)
	}
	if res.Account.Email != "" || res.Account.Project != "p" {
		t.Fatalf("account = %+v", res.Account)
	}
}

// TestAwaitCallbackErrorPropagates covers AwaitCallback's error path.
func TestAwaitCallbackErrorPropagates(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{})
	if _, err := flow.AwaitCallback(context.Background(), contracts.AuthChallenge{}, contracts.ProviderDescriptor{}); err == nil {
		t.Fatal("expected the embedded PKCE error")
	}
}

// TestFetchUserInfoErrorBranches covers the transport and read failures.
func TestFetchUserInfoErrorBranches(t *testing.T) {
	// Transport failure.
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{UserInfoEndpoint: "http://bad host/x"})
	if _, err := flow.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("bad URL accepted")
	}

	// Non-2xx.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	flow2 := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{UserInfoEndpoint: srv.URL})
	if _, err := flow2.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("non-2xx accepted")
	}

	// Invalid JSON.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{")) }))
	defer srv2.Close()
	flow3 := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{UserInfoEndpoint: srv2.URL})
	if _, err := flow3.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

// TestLoadCodeAssistNoEndpoint covers the empty-endpoint guard.
func TestLoadCodeAssistNoEndpoint(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{})
	p, tier := flow.loadCodeAssist(context.Background(), "t")
	if p != "" || tier != "" {
		t.Fatalf("p=%q tier=%q", p, tier)
	}
}

// TestLoadCodeAssistBadJSON covers the unmarshal failure.
func TestLoadCodeAssistBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer srv.Close()
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{LoadCodeAssistEndpoint: srv.URL})
	p, tier := flow.loadCodeAssist(context.Background(), "t")
	if p != "" || tier != "" {
		t.Fatalf("p=%q tier=%q", p, tier)
	}
}

// TestCompanionProjectUnmarshal covers the null/empty and object/string shapes.
func TestCompanionProjectUnmarshal(t *testing.T) {
	var c companionProject
	if err := c.UnmarshalJSON([]byte("null")); err != nil || c.ID != "" || c.Str != "" {
		t.Fatalf("null: %+v %v", c, err)
	}
	var c2 companionProject
	if err := c2.UnmarshalJSON([]byte(`"proj"`)); err != nil || c2.Str != "proj" {
		t.Fatalf("string: %+v %v", c2, err)
	}
	var c3 companionProject
	if err := c3.UnmarshalJSON([]byte(`{"id":"pid"}`)); err != nil || c3.ID != "pid" {
		t.Fatalf("object: %+v %v", c3, err)
	}
	var c4 companionProject
	if err := c4.UnmarshalJSON([]byte(`{bad`)); err == nil {
		t.Fatal("malformed object accepted")
	}
	var c5 companionProject
	if err := c5.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Fatal("malformed string accepted")
	}
}

// TestOnboardAttemptsDefaultAndRetry covers attempts<=0 and the retry path.
func TestOnboardAttemptsDefaultAndRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"done": false}) // never done
	}))
	defer srv.Close()
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{
		OnboardUserEndpoint: srv.URL, OnboardAttempts: 0, OnboardRetryDelay: time.Millisecond,
	})
	flow.onboardUserAsync(context.Background(), "tok", "tier")
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("attempts<=0 should default to 1, hits=%d", hits)
	}
}

// TestPostJSONWithBranches covers the transport, read and non-2xx failures.
func TestPostJSONWithBranches(t *testing.T) {
	if _, ok := postJSONWith(context.Background(), testDoer(t), "http://bad host/x", "ua", "t", []byte(`{}`)); ok {
		t.Fatal("bad URL should fail")
	}
	// Non-2xx.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	if _, ok := postJSONWith(context.Background(), testDoer(t), srv.URL, "", "t", []byte(`{}`)); ok {
		t.Fatal("non-2xx should fail")
	}
	// Success without a UA.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv2.Close()
	if _, ok := postJSONWith(context.Background(), testDoer(t), srv2.URL, "", "t", []byte(`{}`)); !ok {
		t.Fatal("success should report ok")
	}
}

// TestMarshalSeamError covers the graceful degradation when a discovery payload
// cannot be marshalled.
func TestMarshalSeamError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errStubMarshal }
	defer func() { jsonMarshal = orig }()

	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{LoadCodeAssistEndpoint: "https://x"})
	if p, _ := flow.loadCodeAssist(context.Background(), "t"); p != "" {
		t.Fatal("loadCodeAssist should degrade to empty on a marshal error")
	}
}

var errStubMarshal = errors.New("stub marshal failure")

// TestDeviceRefreshClientSecret covers the shared refresh's client_secret branch.
func TestDeviceRefreshClientSecret(t *testing.T) {
	var last url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		last = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "expires_in": 3600})
	}))
	defer srv.Close()

	flow := &DeviceCodeFlow{deps: testDeps(), tokenEndpoint: srv.URL, clientID: "cid", clientSecret: "SEC", requiresClientSecret: true}
	cred := contracts.Credential{ID: "c", Provider: "antigravity"}
	if _, err := flow.Refresh(context.Background(), cred, contracts.RefreshToken{Token: contracts.Secret("r")}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if last.Get("client_secret") != "SEC" {
		t.Fatalf("client_secret = %q", last.Get("client_secret"))
	}
}

// errRoundTripper forces a transport error from the HTTP client.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, errStubMarshal }

// bodyErrRoundTripper returns a response whose body fails on read.
type bodyErrRoundTripper struct{}

func (bodyErrRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: errReader{}}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errStubMarshal }
func (errReader) Close() error             { return nil }

// TestFetchUserInfoTransportAndReadErrors covers the two read failures.
func TestFetchUserInfoTransportAndReadErrors(t *testing.T) {
	deps := testDeps()
	deps.HTTP = &http.Client{Transport: errRoundTripper{}}
	flow := NewAntigravityFlow(deps, antigravityDesc(), AntigravityConfig{UserInfoEndpoint: "https://x/userinfo"})
	if _, err := flow.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("transport error not surfaced")
	}

	deps2 := testDeps()
	deps2.HTTP = &http.Client{Transport: bodyErrRoundTripper{}}
	flow2 := NewAntigravityFlow(deps2, antigravityDesc(), AntigravityConfig{UserInfoEndpoint: "https://x/userinfo"})
	if _, err := flow2.fetchUserInfo(context.Background(), "t"); err == nil {
		t.Fatal("read error not surfaced")
	}
}

// TestPostJSONWithTransportAndReadErrors covers postJSONWith's failures.
func TestPostJSONWithTransportAndReadErrors(t *testing.T) {
	c1 := &http.Client{Transport: errRoundTripper{}}
	if _, ok := postJSONWith(context.Background(), c1, "https://x", "ua", "t", []byte("{}")); ok {
		t.Fatal("transport error should not be ok")
	}
	c2 := &http.Client{Transport: bodyErrRoundTripper{}}
	if _, ok := postJSONWith(context.Background(), c2, "https://x", "ua", "t", []byte("{}")); ok {
		t.Fatal("read error should not be ok")
	}
}

// TestOnboardMarshalError covers the goroutine's marshal-error early return.
func TestOnboardMarshalError(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{OnboardUserEndpoint: "https://x", OnboardAttempts: 1})
	flow.marshal = func(any) ([]byte, error) { return nil, errStubMarshal }
	flow.onboardUserAsync(context.Background(), "t", "tier")
	time.Sleep(20 * time.Millisecond) // must not panic
}

// TestOnboardRetrySleep covers the inter-attempt retry path.
func TestOnboardRetrySleep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"done": false})
	}))
	defer srv.Close()
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{
		OnboardUserEndpoint: srv.URL, OnboardAttempts: 2, OnboardRetryDelay: time.Millisecond,
	})
	flow.onboardUserAsync(context.Background(), "t", "tier")
	time.Sleep(60 * time.Millisecond)
}

// TestAntigravityAwaitCallbackEndToEnd drives the full flow: browser callback,
// token exchange, then the post-exchange against test servers.
func TestAntigravityAwaitCallbackEndToEnd(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 3600})
	}))
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "userinfo"):
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sub", "email": "e@x"})
		case strings.Contains(r.URL.Path, "/lca"):
			_ = json.NewEncoder(w).Encode(map[string]any{"cloudaicompanionProject": "proj"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
		}
	}))
	defer apiSrv.Close()

	desc := contracts.ProviderDescriptor{
		ClientID: "cid", AuthEndpoint: "https://auth.example.test/authorize",
		TokenEndpoint: tokenSrv.URL, RedirectAllowlist: []string{"http://127.0.0.1/callback"},
	}
	cfg := AntigravityConfig{
		UserInfoEndpoint: apiSrv.URL + "/userinfo", LoadCodeAssistEndpoint: apiSrv.URL + "/lca",
		OnboardUserEndpoint: apiSrv.URL + "/onboard", OnboardAttempts: 1, OnboardRetryDelay: time.Millisecond,
	}
	flow := NewAntigravityFlow(testDeps(), desc, cfg)
	flow.CallbackTimeout = 5 * time.Second
	listen, portCh := observeListen(t)
	flow.Listen = listen

	ch, err := flow.Begin(context.Background(), desc)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	type out struct {
		res contracts.AuthResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := flow.AwaitCallback(context.Background(), ch, desc)
		done <- out{res, err}
	}()
	port := <-portCh
	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?state=" + url.QueryEscape(ch.State) + "&code=c")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()

	got := <-done
	if got.err != nil {
		t.Fatalf("AwaitCallback: %v", got.err)
	}
	if got.res.Access.Reveal() != "at" {
		t.Fatalf("access = %q", got.res.Access.Reveal())
	}
	if got.res.Account.Project != "proj" || got.res.Account.Email != "e@x" {
		t.Fatalf("account = %+v", got.res.Account)
	}
}

// TestOnboardNilMarshalFallsBack covers the defensive fallback when a flow was
// constructed without NewAntigravityFlow (nil marshal field).
func TestOnboardNilMarshalFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
	}))
	defer srv.Close()
	flow := &AntigravityFlow{
		cfg:  AntigravityConfig{OnboardUserEndpoint: srv.URL, OnboardAttempts: 1},
		deps: testDeps(),
	}
	flow.onboardUserAsync(context.Background(), "t", "tier")
	time.Sleep(40 * time.Millisecond) // must not panic
}

// testDoer returns a plain (test-only) doer for the low-level postJSONWith tests.
func testDoer(t *testing.T) contracts.HTTPDoer {
	t.Helper()
	d, err := testDeps().doerFor("https://example.test")
	if err != nil {
		t.Fatalf("doerFor: %v", err)
	}
	return d
}
