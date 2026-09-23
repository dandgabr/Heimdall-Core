package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// The BD-02 hermetic end-to-end login rig: an httptest server stands in for
// Google's OAuth token endpoint AND the Antigravity post-exchange hosts
// (userinfo / loadCodeAssist / onboardUser). The app's FlowDeps.HTTP wins over
// the egress policy, so every OAuth call lands here and nothing touches the
// network. The client secret is the same NON-SECRET test placeholder the
// readiness tests inject.

// loginFake is the scripted Google: counters for the exchange/refresh split,
// plus a knob for whether the refresh ROTATES the refresh token.
type loginFake struct {
	exchanges   int32
	refreshes   int32
	rotate      bool // refresh replies with a NEW refresh token when true
	sleep       time.Duration
	mu          sync.Mutex
	lastRefresh string // refresh token presented on the last refresh grant
}

func (f *loginFake) handler(t *testing.T) http.Handler {
	t.Helper()
	// One catch-all handler matched by path SUBSTRING: the descriptor carries
	// the real Google paths (/token, /oauth2/v1/userinfo,
	// /v1internal:loadCodeAssist, /v1internal:onboardUser) and the rewrite
	// doer below only swaps the authority.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = r.ParseForm()
			if got := r.PostForm.Get("client_secret"); got != testAntigravitySecret {
				t.Errorf("token endpoint saw client_secret %q, want the config-injected value", got)
			}
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				atomic.AddInt32(&f.exchanges, 1)
				if r.PostForm.Get("code") == "" {
					t.Error("exchange carried no code")
				}
				if r.PostForm.Get("code_verifier") == "" {
					t.Error("exchange carried no PKCE verifier")
				}
				_, _ = w.Write([]byte(`{"access_token":"AT-1","refresh_token":"RT-1","expires_in":3600,"scope":"cloud-platform"}`))
			case "refresh_token":
				atomic.AddInt32(&f.refreshes, 1)
				f.mu.Lock()
				f.lastRefresh = r.PostForm.Get("refresh_token")
				f.mu.Unlock()
				if r.PostForm.Get("refresh_token") == "RT-REVOKED" {
					// RFC 6749 §5.2: a rejected refresh token.
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				if f.sleep > 0 {
					time.Sleep(f.sleep)
				}
				body := `{"access_token":"AT-2","expires_in":3600}`
				if f.rotate {
					body = `{"access_token":"AT-2","refresh_token":"RT-2","expires_in":3600}`
				}
				_, _ = w.Write([]byte(body))
			default:
				t.Errorf("unexpected grant_type %q", r.PostForm.Get("grant_type"))
			}
		case strings.HasSuffix(r.URL.Path, "/userinfo"):
			_, _ = w.Write([]byte(`{"id":"sub-42","email":"dev@example.com"}`))
		case strings.Contains(r.URL.Path, "loadCodeAssist"):
			_, _ = w.Write([]byte(`{"cloudaicompanionProject":{"id":"proj-xyz"},"allowedTiers":[{"id":"std-tier","isDefault":true}]}`))
		case strings.Contains(r.URL.Path, "onboardUser"):
			_, _ = w.Write([]byte(`{"done":true}`))
		default:
			t.Errorf("unexpected fake-Google path %q", r.URL.Path)
		}
	})
}

// rewriteDoer forces every request onto the fake server regardless of the
// absolute URL the descriptor declares: the OAuth flows keep their real
// endpoint constants and NOTHING leaves the process (hermetic suite).
type rewriteDoer struct {
	target *httptest.Server
	inner  *http.Client
}

func (d rewriteDoer) Do(req *http.Request) (*http.Response, error) {
	su, err := url.Parse(d.target.URL)
	if err != nil {
		return nil, err
	}
	r2 := req.Clone(req.Context())
	r2.URL = req.URL.JoinPath()
	r2.URL.Host = su.Host
	r2.URL.Scheme = su.Scheme
	return d.inner.Do(r2)
}

// buildLoginApp boots an app whose Antigravity OAuth flow points at the fake
// Google. secretMode selects how the operator client secret is supplied:
// "direct" (config value), "env" (client_secret_env naming an env var), or ""
// (absent — the fail-closed tests).
func buildLoginApp(t *testing.T, fake *loginFake, secretMode string, env map[string]string) *App {
	t.Helper()
	if env == nil {
		env = map[string]string{}
	}
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	pc := config.ProviderConfig{ID: "antigravity"}
	switch secretMode {
	case "direct":
		pc.ClientSecret = testAntigravitySecret
	case "env":
		// The secret comes from a NAMED env var (client_secret_env); the value
		// lives in the injected env snapshot, never in the file.
		pc.ClientSecretEnv = "TEST_ANTIGRAVITY_SECRET"
		env["TEST_ANTIGRAVITY_SECRET"] = testAntigravitySecret
	}
	cfg.Providers = []config.ProviderConfig{pc}

	// The fake Google: the rewrite doer forces every OAuth call (token,
	// userinfo, loadCodeAssist, onboarding, refresh) onto this server, so the
	// descriptor's googleapis hosts never dial out.
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)

	salt, _ := secret.NewSalt()
	instance, err := Build(Options{
		Config: cfg,
		Env:    env,
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				KeyFilePath:      filepath.Join(dir, "master-key"),
				AllowEnvOverride: true,
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "login-test-material"},
			},
		},
		FlowDeps: &oauth.ClientDeps{HTTP: rewriteDoer{target: srv, inner: srv.Client()}, AllowLoopback: true},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// openStoredBlob decrypts a stored OAuth credential through the app's vault.
func openStoredBlob(t *testing.T, a *App, cred contracts.Credential) contracts.CredentialBlob {
	t.Helper()
	plaintext, err := a.Secrets.Open(string(cred.Sealed))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	blob, err := contracts.ParseCredentialBlob(plaintext)
	if err != nil {
		t.Fatalf("ParseCredentialBlob: %v", err)
	}
	return blob
}

// loginPasted drives one full login through the paste-code path.
func loginPasted(t *testing.T, a *App) LoginResult {
	t.Helper()
	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	res, err := session.Complete(context.Background(), "auth-code-1")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return res
}

// TestLoginEndToEndPastedCode is the BD-02 §1 acceptance path: Begin prints a
// real authorization URL, the pasted code completes the grant, and the
// credential lands SEALED in the vault with the enriched identity — ready.
func TestLoginEndToEndPastedCode(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	// The authorization URL is the provider's (Google) endpoint with the
	// public client id — never the token endpoint, never a secret.
	if !strings.HasPrefix(session.AuthURL(), "https://accounts.google.com/") {
		t.Fatalf("auth url = %q", session.AuthURL())
	}
	u, _ := url.Parse(session.AuthURL())
	if u.Query().Get("client_id") == "" || u.Query().Get("state") == "" {
		t.Fatalf("auth url missing client_id/state: %q", session.AuthURL())
	}
	if session.RiskNotice() != "provider.risk_notice.antigravity" {
		t.Fatalf("risk notice = %q", session.RiskNotice())
	}

	res, err := session.Complete(context.Background(), "auth-code-1")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Provider != "antigravity" || res.Email != "dev@example.com" || res.Project != "proj-xyz" || res.Plan != "std-tier" {
		t.Fatalf("result = %+v", res)
	}
	if atomic.LoadInt32(&fake.exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1", fake.exchanges)
	}

	// The stored credential: metadata enriched, blob sealed (access+refresh).
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cred.AuthMode != contracts.AuthOAuth || cred.Provider != "antigravity" {
		t.Fatalf("credential = %+v", cred)
	}
	if cred.Meta.Project != "proj-xyz" || cred.Meta.Plan != "std-tier" || cred.Meta.Email != "dev@example.com" {
		t.Fatalf("meta = %+v", cred.Meta)
	}
	blob := openStoredBlob(t, a, cred)
	if blob.AccessToken != "AT-1" || blob.RefreshToken != "RT-1" {
		t.Fatalf("blob = %+v", blob)
	}

	// The raw vault file must NOT contain either token.
	raw, err := os.ReadFile(a.Config.Store.Path)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	for _, secretValue := range []string{"AT-1", "RT-1"} {
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("plaintext token %q leaked into the vault file", secretValue)
		}
	}

	// Ready after login; the same rule on both views.
	if s := readyByID(a.ProviderStatus(context.Background()))["antigravity"]; !s.Ready {
		t.Fatalf("status after login = %+v, want ready", s)
	}

	// --status: logged in, non-secret fields only, not expired.
	st, err := a.LoginStatus(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("LoginStatus: %v", err)
	}
	if !st.LoggedIn || st.Email != "dev@example.com" || st.Project != "proj-xyz" || st.Plan != "std-tier" || st.Expired {
		t.Fatalf("status = %+v", st)
	}
	if st.ExpiresAt.IsZero() {
		t.Fatal("status lost the access-token expiry")
	}
}

// TestLoginIdempotent proves re-logging the same account UPDATES the same
// credential row instead of duplicating it.
func TestLoginIdempotent(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	first := loginPasted(t, a)
	second := loginPasted(t, a)
	if first.CredentialID != second.CredentialID {
		t.Fatalf("ids differ: %q vs %q", first.CredentialID, second.CredentialID)
	}
	if first.Upserted || !second.Upserted {
		t.Fatalf("Upserted = %v, %v (want false then true)", first.Upserted, second.Upserted)
	}
	creds, err := a.Credentials.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials = %d, want 1 (idempotent re-login)", len(creds))
	}
}

// TestLoginCallbackPath drives the loopback callback like a browser: Complete
// waits, the GET with the right state completes it, the grant persists.
func TestLoginCallbackPath(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	u, _ := url.Parse(session.AuthURL())
	state := u.Query().Get("state")

	type outcome struct {
		res LoginResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := session.Complete(context.Background(), "")
		done <- outcome{res, err}
	}()

	callback := session.CallbackURI() + "?code=auth-code-1&state=" + url.QueryEscape(state)
	resp, err := http.Get(callback) //nolint:noctx // test-local loopback GET
	if err != nil {
		t.Fatalf("browser GET: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case out := <-done:
		if out.err != nil {
			t.Fatalf("Complete: %v", out.err)
		}
		if out.res.Email != "dev@example.com" || out.res.Project != "proj-xyz" {
			t.Fatalf("result = %+v", out.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Complete did not return after the callback")
	}
}

// TestLoginCallbackStateMismatch proves a forged/replayed callback (wrong
// state) fails the grant with auth.oauth_state_mismatch and stores nothing.
func TestLoginCallbackStateMismatch(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	type outcome struct {
		res LoginResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := session.Complete(context.Background(), "")
		done <- outcome{res, err}
	}()

	callback := session.CallbackURI() + "?code=auth-code-1&state=forged-state"
	resp, err := http.Get(callback) //nolint:noctx // test-local loopback GET
	if err != nil {
		t.Fatalf("browser GET: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case out := <-done:
		if out.err == nil || !hasCode(out.err, domain.CodeAuthStateMismatch) {
			t.Fatalf("err = %v, want %s", out.err, domain.CodeAuthStateMismatch)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Complete did not return after the forged callback")
	}
	creds, _ := a.Credentials.List(context.Background())
	if len(creds) != 0 {
		t.Fatalf("a forged callback stored %d credentials", len(creds))
	}
}

// TestLoginFailsClosedWithoutClientSecret proves the missing operator secret
// refuses the login BEFORE any network I/O (ADR-0003 emenda).
func TestLoginFailsClosedWithoutClientSecret(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "", nil)

	if _, err := a.BeginLogin(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeAuthProviderClientSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthProviderClientSecretMissing)
	}
	if atomic.LoadInt32(&fake.exchanges) != 0 {
		t.Fatal("the flow reached the token endpoint without a client secret")
	}
}

// TestLoginSecretFromEnv proves the client_secret_env resolution path end to
// end: the file carries only the VARIABLE NAME; the value rides the env.
func TestLoginSecretFromEnv(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "env", nil)
	res := loginPasted(t, a)
	if res.Email != "dev@example.com" {
		t.Fatalf("result = %+v", res)
	}
}

// TestLoginRefusesAPIKeyProvider proves `login` on an API-key provider is a
// typed refusal pointing at `provider add-key`.
func TestLoginRefusesAPIKeyProvider(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	if _, err := a.BeginLogin(context.Background(), "z.ai"); err == nil || !hasCode(err, domain.CodeProviderLoginNotSupported) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderLoginNotSupported)
	}
}

// TestLoginUnknownProvider covers the registry lookup failure.
func TestLoginUnknownProvider(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	if _, err := a.BeginLogin(context.Background(), "nope"); err == nil || !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNotFound)
	}
}

// TestLoginWithoutKEK proves login refuses when the credential could not be
// sealed (a fresh vault with no key configured leaves Secrets nil).
func TestLoginWithoutKEK(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Providers = []config.ProviderConfig{{ID: "antigravity", ClientSecret: testAntigravitySecret}}

	srv := httptest.NewServer((&loginFake{}).handler(t))
	t.Cleanup(srv.Close)
	instance, err := Build(Options{
		Config:   cfg,
		Env:      map[string]string{},
		FlowDeps: &oauth.ClientDeps{HTTP: rewriteDoer{target: srv, inner: srv.Client()}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	// A fresh empty vault boots with Secrets nil; login must fail closed.
	if _, err := instance.BeginLogin(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeConfigSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeConfigSecretMissing)
	}
}

// TestLoginStatusWithoutCredential covers the logged-out status rows for both
// provider kinds.
func TestLoginStatusWithoutCredential(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	st, err := a.LoginStatus(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("LoginStatus: %v", err)
	}
	if st.LoggedIn || st.ReasonCode != domain.CodeProviderLoginRequired {
		t.Fatalf("antigravity status = %+v, want logged out (%s)", st, domain.CodeProviderLoginRequired)
	}
	st, err = a.LoginStatus(context.Background(), "z.ai")
	if err != nil {
		t.Fatalf("LoginStatus: %v", err)
	}
	if st.LoggedIn || st.ReasonCode != domain.CodeProviderNoCredential {
		t.Fatalf("z.ai status = %+v, want logged out (%s)", st, domain.CodeProviderNoCredential)
	}
}

// --- refresh (BD-02 §3) ---

// TestCredentialRefresher is the BD02-1 adapter test: the port runs the
// single-flight refresh and returns the PERSISTED renewed credential; on a
// refresh failure it returns the original credential alongside the error (the
// executor fails open with it).
func TestCredentialRefresher(t *testing.T) {
	fake := &loginFake{rotate: true}
	a := buildLoginApp(t, fake, "direct", nil)
	res := loginPasted(t, a)
	r := credentialRefresher{app: a}
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	fresh, err := r.RefreshCredential(context.Background(), cred)
	if err != nil {
		t.Fatalf("RefreshCredential: %v", err)
	}
	if fresh.ID != cred.ID || fresh.Provider != "antigravity" {
		t.Fatalf("fresh = %+v, want the same credential row renewed", fresh)
	}
	blob := openStoredBlob(t, a, fresh)
	if blob.AccessToken != "AT-2" || blob.RefreshToken != "RT-2" {
		t.Fatalf("blob = %+v, want the rotated pair", blob)
	}
	if atomic.LoadInt32(&fake.refreshes) != 1 {
		t.Fatalf("upstream refreshes = %d, want 1", fake.refreshes)
	}

	// Failure branch: without the operator client secret the refresh fails
	// closed and the ORIGINAL credential comes back with the error.
	noSecret := buildLoginApp(t, &loginFake{}, "", nil)
	origID := sealOAuthRaw(t, noSecret, "antigravity", []byte(`{"access_token":"AT-9","refresh_token":"RT-9"}`))
	orig, err := noSecret.Credentials.Get(context.Background(), origID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := credentialRefresher{app: noSecret}.RefreshCredential(context.Background(), orig)
	if !hasCode(err, domain.CodeAuthProviderClientSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthProviderClientSecretMissing)
	}
	if got.ID != orig.ID || string(got.Sealed) != string(orig.Sealed) {
		t.Fatalf("got = %+v, want the original credential unchanged", got)
	}
}

// TestRefreshSingleFlightAndRotation is the §3 acceptance test: N concurrent
// refreshers produce EXACTLY ONE upstream exchange; the rotated refresh token
// replaces the stored one; the projectId/tier survive in Meta.
func TestRefreshSingleFlightAndRotation(t *testing.T) {
	fake := &loginFake{rotate: true, sleep: 250 * time.Millisecond}
	a := buildLoginApp(t, fake, "direct", nil)
	res := loginPasted(t, a)
	if atomic.LoadInt32(&fake.exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1", fake.exchanges)
	}

	const callers = 4
	results := make([]RefreshResult, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = a.RefreshProvider(context.Background(), "antigravity")
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
	}
	// Single-flight: exactly one exchange reached the token endpoint.
	if n := atomic.LoadInt32(&fake.refreshes); n != 1 {
		t.Fatalf("upstream refreshes = %d, want 1 (callers=%d)", n, callers)
	}
	var winners, collapsed int
	for _, r := range results {
		if r.Collapsed {
			collapsed++
		} else {
			winners++
		}
		if r.ExpiresAt.IsZero() || r.CredentialID != res.CredentialID {
			t.Fatalf("result = %+v", r)
		}
	}
	if winners != 1 || collapsed != callers-1 {
		t.Fatalf("winners=%d collapsed=%d, want 1 and %d", winners, collapsed, callers-1)
	}

	// The rotated refresh token replaced the stored one; the identity survived.
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	blob := openStoredBlob(t, a, cred)
	if blob.AccessToken != "AT-2" || blob.RefreshToken != "RT-2" {
		t.Fatalf("blob = %+v, want the rotated pair", blob)
	}
	if cred.Meta.Project != "proj-xyz" || cred.Meta.Plan != "std-tier" || cred.Meta.Email != "dev@example.com" {
		t.Fatalf("meta after refresh = %+v, want the login identity preserved", cred.Meta)
	}
	// Still ready.
	if s := readyByID(a.ProviderStatus(context.Background()))["antigravity"]; !s.Ready {
		t.Fatalf("status after refresh = %+v, want ready", s)
	}
}

// TestRefreshKeepsUnrotatedToken proves a provider that does NOT rotate keeps
// the stored refresh token (RFC 6749 §6).
func TestRefreshKeepsUnrotatedToken(t *testing.T) {
	fake := &loginFake{rotate: false} // refresh replies WITHOUT a refresh token
	a := buildLoginApp(t, fake, "direct", nil)
	res := loginPasted(t, a)

	if _, err := a.RefreshProvider(context.Background(), "antigravity"); err != nil {
		t.Fatalf("RefreshProvider: %v", err)
	}
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	blob := openStoredBlob(t, a, cred)
	if blob.AccessToken != "AT-2" || blob.RefreshToken != "RT-1" {
		t.Fatalf("blob = %+v, want new access + kept refresh", blob)
	}
	fake.mu.Lock()
	presented := fake.lastRefresh
	fake.mu.Unlock()
	if presented != "RT-1" {
		t.Fatalf("refresh presented %q, want the stored RT-1", presented)
	}
}

// TestRefreshRefusesNoCredentialAndSecret covers the two fail-closed prechecks.
func TestRefreshRefusesNoCredentialAndSecret(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	if _, err := a.RefreshProvider(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeProviderNoCredential) {
		t.Fatalf("no-credential err = %v, want %s", err, domain.CodeProviderNoCredential)
	}
	if _, err := a.RefreshProvider(context.Background(), "z.ai"); err == nil || !hasCode(err, domain.CodeProviderLoginNotSupported) {
		t.Fatalf("api-key err = %v, want %s", err, domain.CodeProviderLoginNotSupported)
	}

	// A credential present but the secret gone (config changed): fail closed
	// BEFORE any network call.
	noSecret := buildLoginApp(t, &loginFake{}, "", nil)
	_ = sealOAuthRaw(t, noSecret, "antigravity", []byte(`{"access_token":"AT-9","refresh_token":"RT-9"}`))
	if _, err := noSecret.RefreshProvider(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeAuthProviderClientSecretMissing) {
		t.Fatalf("no-secret err = %v, want %s", err, domain.CodeAuthProviderClientSecretMissing)
	}
	if atomic.LoadInt32(&fake.refreshes) != 0 {
		t.Fatal("the no-secret refresh reached the token endpoint")
	}
}

// TestRefreshRefusesCorruptBlob proves a malformed stored document fails with
// auth.credential_invalid (re-login), never an empty bearer upstream.
func TestRefreshRefusesCorruptBlob(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`this is not json`))
	if _, err := a.RefreshProvider(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeAuthCredentialInvalid) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthCredentialInvalid)
	}
	if atomic.LoadInt32(&fake.refreshes) != 0 {
		t.Fatal("the corrupt credential reached the token endpoint")
	}
}

// TestRefreshRefusesMissingRefreshToken covers the "no refresh token stored"
// branch: the access token alone cannot renew.
func TestRefreshRefusesMissingRefreshToken(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`{"access_token":"AT-9"}`))
	if _, err := a.RefreshProvider(context.Background(), "antigravity"); err == nil || !hasCode(err, domain.CodeAuthCredentialInvalid) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthCredentialInvalid)
	}
}

// TestRefreshUnknownProvider covers the registry lookup failure.
func TestRefreshUnknownProvider(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	if _, err := a.RefreshProvider(context.Background(), "nope"); err == nil || !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNotFound)
	}
}

// sealOAuthRaw writes an OAuth credential whose sealed blob decrypts to the
// given plaintext, for the failure-branch tests.
func sealOAuthRaw(t *testing.T, a *App, provider domain.ProviderID, plaintext []byte) domain.CredentialID {
	t.Helper()
	sealed, err := a.Secrets.Seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	id := oauthCredentialID(provider, "", "")
	if err := a.Credentials.Upsert(context.Background(), contracts.Credential{
		ID: id, Provider: provider, AuthMode: contracts.AuthOAuth, Label: string(provider),
		Sealed: []byte(sealed), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return id
}

// --- seam-driven branch tests (a real flow never provokes these) ---

// stubOAuthFlow is the common part of the capability stubs.
type stubOAuthFlow struct {
	result contracts.AuthResult
}

func (f *stubOAuthFlow) Kind() contracts.AuthMode { return contracts.AuthOAuth }
func (f *stubOAuthFlow) Begin(context.Context, contracts.ProviderDescriptor) (contracts.AuthChallenge, error) {
	return contracts.AuthChallenge{Mode: contracts.AuthOAuth, State: "s", RedirectURI: "http://127.0.0.1:1/callback"}, nil
}
func (f *stubOAuthFlow) Poll(context.Context, contracts.AuthChallenge) (contracts.AuthResult, error) {
	return contracts.AuthResult{}, nil
}
func (f *stubOAuthFlow) Refresh(context.Context, contracts.Credential, contracts.RefreshToken) (contracts.AuthResult, error) {
	return contracts.AuthResult{}, nil
}

// stubNeither implements no completion capability.
type stubNeither struct{ stubOAuthFlow }

// Close satisfies the release interface, so the refusal branch's cleanup runs.
func (f *stubNeither) Close() error { return nil }

// stubAwaiterOnly completes only via the loopback callback.
type stubAwaiterOnly struct{ stubOAuthFlow }

func (f *stubAwaiterOnly) AwaitCallback(context.Context, contracts.AuthChallenge, contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	return f.result, nil
}

// stubExchangerOnly completes only via a pasted code.
type stubExchangerOnly struct{ stubOAuthFlow }

func (f *stubExchangerOnly) ExchangeCode(context.Context, contracts.AuthChallenge, string, contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	return f.result, nil
}

// withLoginFlow swaps the login flow seam for the given flow.
func withLoginFlow(t *testing.T, flow contracts.AuthFlow) {
	t.Helper()
	original := loginFlowBuilder
	loginFlowBuilder = func(*App, domain.ProviderID) (contracts.AuthFlow, error) { return flow, nil }
	t.Cleanup(func() { loginFlowBuilder = original })
}

// TestBeginLoginRefusesIncapableFlow proves a flow with neither completion
// capability is refused before a grant can hang.
func TestBeginLoginRefusesIncapableFlow(t *testing.T) {
	a := buildLoginApp(t, &loginFake{}, "direct", nil)
	withLoginFlow(t, &stubNeither{})
	if _, err := a.BeginLogin(context.Background(), "antigravity"); !hasCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// TestCompleteRefusesPastedCodeOnAwaiterOnly covers the exchanger-missing
// branch of Complete.
func TestCompleteRefusesPastedCodeOnAwaiterOnly(t *testing.T) {
	a := buildLoginApp(t, &loginFake{}, "direct", nil)
	withLoginFlow(t, &stubAwaiterOnly{stubOAuthFlow{result: contracts.AuthResult{Access: contracts.Secret("x"), AuthMode: contracts.AuthOAuth}}})
	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, err := session.Complete(context.Background(), "pasted"); !hasCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// TestCompleteRefusesCallbackOnExchangerOnly covers the awaiter-missing branch
// of Complete.
func TestCompleteRefusesCallbackOnExchangerOnly(t *testing.T) {
	a := buildLoginApp(t, &loginFake{}, "direct", nil)
	withLoginFlow(t, &stubExchangerOnly{stubOAuthFlow{result: contracts.AuthResult{Access: contracts.Secret("x"), AuthMode: contracts.AuthOAuth}}})
	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, err := session.Complete(context.Background(), ""); !hasCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// TestBeginLoginDescriptorError covers the descriptor-lookup failure branch.
func TestBeginLoginDescriptorError(t *testing.T) {
	a := buildLoginApp(t, &loginFake{}, "direct", nil)
	a.descriptor = func(domain.ProviderID) (contracts.ProviderDescriptor, error) {
		return contracts.ProviderDescriptor{}, domain.New(domain.CodeProviderNotFound, domain.WithHTTPStatus(404))
	}
	if _, err := a.BeginLogin(context.Background(), "antigravity"); !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNotFound)
	}
}

// TestBeginLoginBeginError covers the flow Begin failure branch (an injected
// descriptor without an authorization endpoint makes Begin fail insecure).
func TestBeginLoginBeginError(t *testing.T) {
	a := buildLoginApp(t, &loginFake{}, "direct", nil)
	a.descriptor = func(id domain.ProviderID) (contracts.ProviderDescriptor, error) {
		desc, err := auth.Descriptor(id)
		if err != nil {
			return desc, err
		}
		desc.AuthEndpoint = ""
		return desc, nil
	}
	if _, err := a.BeginLogin(context.Background(), "antigravity"); !hasCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// TestCompletePersistErrors covers the seal and upsert failure branches of the
// persist path.
func TestCompletePersistErrors(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)

	// Seal failure via the injected seamer.
	session, err := a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	a.sealer = failingSealer{}
	if _, err := session.Complete(context.Background(), "auth-code-1"); !hasCode(err, domain.CodeCredentialStoreFailed) {
		t.Fatalf("seal err = %v, want %s", err, domain.CodeCredentialStoreFailed)
	}
	a.sealer = nil

	// Encode failure via the encoder seam.
	origEncode := encodeCredentialBlob
	encodeCredentialBlob = func(contracts.CredentialBlob) ([]byte, error) {
		return nil, domain.New(domain.CodeInternal, domain.WithHTTPStatus(500))
	}
	session, err = a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, err := session.Complete(context.Background(), "auth-code-1"); !hasCode(err, domain.CodeCredentialStoreFailed) {
		t.Fatalf("encode err = %v, want %s", err, domain.CodeCredentialStoreFailed)
	}
	encodeCredentialBlob = origEncode

	// Upsert failure via a closed vault.
	session, err = a.BeginLogin(context.Background(), "antigravity")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	_ = a.Store.Close()
	if _, err := session.Complete(context.Background(), "auth-code-1"); err == nil || !hasCode(err, domain.CodeCredentialStoreFailed) {
		t.Fatalf("upsert err = %v, want %s", err, domain.CodeCredentialStoreFailed)
	}
}

// TestPersistLoginLabelFallback covers the label fallback when the provider
// returned no email: the label is the provider id.
func TestPersistLoginLabelFallback(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	res, err := a.persistLogin(context.Background(), "antigravity", contracts.AuthResult{
		Access:   contracts.Secret("AT-x"),
		Token:    contracts.RefreshToken{Token: contracts.Secret("RT-x"), Rotated: true},
		AuthMode: contracts.AuthOAuth,
	})
	if err != nil {
		t.Fatalf("persistLogin: %v", err)
	}
	if res.Label != "antigravity" {
		t.Fatalf("label = %q, want the provider id fallback", res.Label)
	}
	cred, err := a.Credentials.Get(context.Background(), res.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cred.Meta.DisplayName != "antigravity" {
		t.Fatalf("display name = %q", cred.Meta.DisplayName)
	}
}

// TestLoginStatusErrorBranches covers the vault-error and wrong-mode branches
// of LoginStatus.
func TestLoginStatusErrorBranches(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	ctx := context.Background()

	// Unknown provider: the registry lookup error propagates.
	if _, err := a.LoginStatus(ctx, "nope"); !hasCode(err, domain.CodeProviderNotFound) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNotFound)
	}

	// A vault read error is surfaced, never reported as logged out.
	_ = a.Store.Close()
	if _, err := a.LoginStatus(ctx, "antigravity"); err == nil {
		t.Fatal("LoginStatus swallowed a vault read error")
	}

	// A stored credential whose mode is not OAuth is reported as invalid.
	a2 := buildLoginApp(t, &loginFake{}, "direct", nil)
	keySealed, err := a2.Secrets.Seal([]byte("key-material"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := a2.Credentials.Upsert(ctx, contracts.Credential{
		ID: "keyed", Provider: "antigravity", AuthMode: contracts.AuthAPIKey, Sealed: []byte(keySealed),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	st, err := a2.LoginStatus(ctx, "antigravity")
	if err != nil {
		t.Fatalf("LoginStatus: %v", err)
	}
	if st.LoggedIn || st.ReasonCode != domain.CodeCredentialInvalidAuthMode {
		t.Fatalf("status = %+v, want invalid_auth_mode", st)
	}
}

// TestRefreshRereadFailureBranches covers the three failure branches AFTER the
// single-flight lock: a row swapped to a corrupt blob under the lock, a
// revoked refresh token, and a persist failure.
func TestRefreshRereadFailureBranches(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	ctx := context.Background()
	credID := oauthCredentialID("antigravity", "", "")

	// (a) The row changes to a corrupt blob while the caller waits on the
	// lock: the re-read fails closed.
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`{"access_token":"AT-1","refresh_token":"RT-1"}`))
	unlock, err := a.Credentials.RefreshLock(ctx, credID)
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := a.RefreshProvider(ctx, "antigravity")
		errCh <- err
	}()
	// Bounded wait for the goroutine to park on the refresh lock.
	time.Sleep(100 * time.Millisecond)
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`corrupt after snapshot`))
	unlock()
	if err := <-errCh; err == nil || !hasCode(err, domain.CodeAuthCredentialInvalid) {
		t.Fatalf("corrupt re-read err = %v, want %s", err, domain.CodeAuthCredentialInvalid)
	}

	// (b) A revoked refresh token: the flow's typed error propagates.
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`{"access_token":"AT-1","refresh_token":"RT-REVOKED"}`))
	if _, err := a.RefreshProvider(ctx, "antigravity"); err == nil || !hasCode(err, domain.CodeAuthCredentialInvalid) {
		t.Fatalf("revoked err = %v, want %s", err, domain.CodeAuthCredentialInvalid)
	}

	// (c) The persist fails after a successful exchange.
	a.sealer = failingSealer{}
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`{"access_token":"AT-1","refresh_token":"RT-1"}`))
	if _, err := a.RefreshProvider(ctx, "antigravity"); err == nil || !hasCode(err, domain.CodeCredentialStoreFailed) {
		t.Fatalf("persist err = %v, want %s", err, domain.CodeCredentialStoreFailed)
	}
	a.sealer = nil
}

// TestRefreshFailureBranches covers the remaining fail-closed prechecks of the
// refresh path.
func TestRefreshFailureBranches(t *testing.T) {
	fake := &loginFake{}
	a := buildLoginApp(t, fake, "direct", nil)
	ctx := context.Background()

	// No KEK.
	a2 := buildLoginApp(t, &loginFake{}, "direct", nil)
	_ = sealOAuthRaw(t, a2, "antigravity", []byte(`{"access_token":"AT-9","refresh_token":"RT-9"}`))
	a2.Secrets = nil
	if _, err := a2.RefreshProvider(ctx, "antigravity"); !hasCode(err, domain.CodeConfigSecretMissing) {
		t.Fatalf("no-kek err = %v, want %s", err, domain.CodeConfigSecretMissing)
	}

	// A stored credential whose mode is not OAuth.
	keySealed, err := a.Secrets.Seal([]byte("key-material"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := a.Credentials.Upsert(ctx, contracts.Credential{
		ID: "keyed", Provider: "antigravity", AuthMode: contracts.AuthAPIKey, Sealed: []byte(keySealed),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := a.RefreshProvider(ctx, "antigravity"); !hasCode(err, domain.CodeCredentialInvalidAuthMode) {
		t.Fatalf("mode err = %v, want %s", err, domain.CodeCredentialInvalidAuthMode)
	}
	_ = a.Credentials.Delete(ctx, "keyed")

	// A blob that the KEK cannot open (sealed under a different key).
	otherSalt, _ := secret.NewSalt()
	otherKEK, _ := secret.DeriveKEK([]byte("other-material"), otherSalt, secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32})
	other, _ := secret.NewWithKEK(otherKEK)
	otherSealed, _ := other.Seal([]byte(`{"access_token":"AT-8","refresh_token":"RT-8"}`))
	if err := a.Credentials.Upsert(ctx, contracts.Credential{
		ID: "alien", Provider: "antigravity", AuthMode: contracts.AuthOAuth, Sealed: []byte(otherSealed),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := a.RefreshProvider(ctx, "antigravity"); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("undecryptable err = %v, want %s", err, domain.CodeAuthSecretMissing)
	}
	_ = a.Credentials.Delete(ctx, "alien")

	// The single-flight lock honours ctx: a cancelled wait refuses.
	_ = sealOAuthRaw(t, a, "antigravity", []byte(`{"access_token":"AT-1","refresh_token":"RT-1"}`))
	unlock, err := a.Credentials.RefreshLock(ctx, oauthCredentialID("antigravity", "", ""))
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := a.RefreshProvider(cctx, "antigravity"); err == nil {
		t.Fatal("a cancelled lock wait must refuse")
	}
	unlock()

	// The re-read under the lock fails when the vault closed while waiting.
	unlock2, err := a.Credentials.RefreshLock(ctx, oauthCredentialID("antigravity", "", ""))
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := a.RefreshProvider(ctx, "antigravity")
		errCh <- err
	}()
	// Bounded wait for the goroutine to park on the refresh lock.
	time.Sleep(100 * time.Millisecond)
	_ = a.Store.Close()
	unlock2()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("the re-read under a broken vault must fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshProvider did not return after the lock release")
	}
}
