package cli

import (
	"context"
	"io"
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

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// The `heimdall login` end-to-end tests (BD-02): the real CLI drives a real
// App whose Antigravity OAuth flow is pointed at a fake Google by the
// buildReadOnly seam. No command ever sees a token in its output.

// cliFakeGoogle mirrors the app package's scripted provider: one catch-all
// handler for the token/userinfo/loadCodeAssist/onboardUser surface.
type cliFakeGoogle struct {
	exchanges int32
}

func (f *cliFakeGoogle) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") == "authorization_code" && r.PostForm.Get("code") != "auth-code-1" {
				// RFC 6749 §5.2: an unknown code is refused.
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			if r.PostForm.Get("client_secret") != "test-only-client-secret-not-real" {
				t.Errorf("token endpoint saw an unexpected client secret")
			}
			atomic.AddInt32(&f.exchanges, 1)
			_, _ = w.Write([]byte(`{"access_token":"CLI-AT-1","refresh_token":"CLI-RT-1","expires_in":3600}`))
		case strings.HasSuffix(r.URL.Path, "/userinfo"):
			_, _ = w.Write([]byte(`{"id":"sub-7","email":"cli@example.com"}`))
		case strings.Contains(r.URL.Path, "loadCodeAssist"):
			_, _ = w.Write([]byte(`{"cloudaicompanionProject":{"id":"proj-cli"},"allowedTiers":[{"id":"std-tier","isDefault":true}]}`))
		case strings.Contains(r.URL.Path, "onboardUser"):
			_, _ = w.Write([]byte(`{"done":true}`))
		default:
			t.Errorf("unexpected fake path %q", r.URL.Path)
		}
	})
}

// cliRewriteDoer forces every OAuth request onto the fake server (hermeticity).
type cliRewriteDoer struct {
	target *httptest.Server
	inner  *http.Client
}

func (d cliRewriteDoer) Do(req *http.Request) (*http.Response, error) {
	su, err := url.Parse(d.target.URL)
	if err != nil {
		return nil, err
	}
	r2 := req.Clone(context.Background())
	r2.URL = req.URL.JoinPath()
	r2.URL.Host = su.Host
	r2.URL.Scheme = su.Scheme
	return d.inner.Do(r2)
}

// installLoginSeam swaps buildReadOnly for a builder that injects the test KEK
// and the fake-Google flow deps, and writes a config file. clientSecret empty
// omits the operator secret from the file (the fail-closed test).
func installLoginSeam(t *testing.T, fake *cliFakeGoogle, clientSecret string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"antigravity\"\n"
	if clientSecret != "" {
		body += "client_secret = \"" + clientSecret + "\"\n"
	}
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)

	original := buildReadOnly
	buildReadOnly = func(configPath string) (*app.App, error) {
		cfg, err := config.Load(config.Options{FilePath: configPath, Env: map[string]string{}})
		if err != nil {
			return nil, err
		}
		salt, _ := secret.NewSalt()
		return app.Build(app.Options{
			Config: cfg,
			Env:    map[string]string{},
			SecretOptions: &secret.Options{
				Salt:   salt,
				Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
				Custody: secret.Custody{
					KeyFilePath:      filepath.Join(dir, "master-key"),
					AllowEnvOverride: true,
					Env:              map[string]string{"HEIMDALL_MASTER_KEY": "cli-login-material"},
				},
			},
			FlowDeps: &oauth.ClientDeps{HTTP: cliRewriteDoer{target: srv, inner: srv.Client()}},
		})
	}
	t.Cleanup(func() { buildReadOnly = original })
	return cfgPath
}

// TestLoginCommandPastedCode is the CLI acceptance path: login completes with a
// pasted code, prints the risk notice + authorization URL + identity line, and
// never a token; --status then reports the stored login.
func TestLoginCommandPastedCode(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "test-only-client-secret-not-real")

	var out strings.Builder
	var errBuf strings.Builder
	code := executeWith(&errBuf, &out, []string{"login", "antigravity", "--code", "auth-code-1", "--config", cfg})
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	text := out.String()
	if !strings.Contains(text, "!") {
		t.Errorf("risk notice missing: %s", text)
	}
	if !strings.Contains(text, "accounts.google.com") {
		t.Errorf("authorization URL missing: %s", text)
	}
	if !strings.Contains(text, "provider=antigravity") || !strings.Contains(text, "email=cli@example.com") || !strings.Contains(text, "project=proj-cli") {
		t.Errorf("identity line missing: %s", text)
	}
	for _, tok := range []string{"CLI-AT-1", "CLI-RT-1", "test-only-client-secret-not-real"} {
		if strings.Contains(text, tok) || strings.Contains(errBuf.String(), tok) {
			t.Fatalf("secret %q leaked into the command output", tok)
		}
	}

	// --status: the stored login, still without any secret material.
	var status strings.Builder
	if code := executeWith(&strings.Builder{}, &status, []string{"login", "antigravity", "--status", "--config", cfg}); code != 0 {
		t.Fatalf("status exit = %d: %s", code, status.String())
	}
	stext := status.String()
	for _, want := range []string{"credential=", "email=cli@example.com", "project=proj-cli", "plan=std-tier", "state=valid"} {
		if !strings.Contains(stext, want) {
			t.Errorf("status missing %q: %s", want, stext)
		}
	}
	for _, tok := range []string{"CLI-AT-1", "CLI-RT-1"} {
		if strings.Contains(stext, tok) {
			t.Fatalf("status leaked %q", tok)
		}
	}

	// The vault file must not carry the plaintext tokens either.
	dbPath := readStorePath(cfg)
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if strings.Contains(string(raw), "CLI-AT-1") || strings.Contains(string(raw), "CLI-RT-1") {
		t.Fatal("the plaintext oauth tokens landed in the vault file")
	}
}

// TestLoginStatusLoggedOut proves the logged-out status row for an OAuth
// provider is the user-fixable login_required reason.
func TestLoginStatusLoggedOut(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "test-only-client-secret-not-real")

	var out strings.Builder
	if code := executeWith(&strings.Builder{}, &out, []string{"login", "antigravity", "--status", "--config", cfg}); code != 0 {
		t.Fatalf("status exit = %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "antigravity\tstate=logged-out\treason=provider.login_required") {
		t.Errorf("status = %q, want the logged-out login_required row", out.String())
	}
}

// TestLoginCommandMissingSecret proves the fail-closed refusal renders as an
// actionable, secret-free message on stderr with a non-zero exit. The KEK is
// present (via the seam); only the operator client secret is missing.
func TestLoginCommandMissingSecret(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "") // NO client secret on purpose

	var out, errBuf strings.Builder
	code := executeWith(&errBuf, &out, []string{"login", "antigravity", "--code", "x", "--config", cfg})
	if code == 0 {
		t.Fatalf("login without a client secret exited 0")
	}
	msg := errBuf.String()
	if !strings.Contains(msg, "client secret") {
		t.Errorf("stderr = %q, want the client-secret-missing message", msg)
	}
}

// TestLoginCommandWithoutKEK proves the KEK precheck refuses the login when
// nothing can be sealed (a fresh vault with no key configured).
func TestLoginCommandWithoutKEK(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"antigravity\"\nclient_secret = \"test-only-client-secret-not-real\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out, errBuf strings.Builder
	code := executeWith(&errBuf, &out, []string{"login", "antigravity", "--code", "x", "--config", cfg})
	if code == 0 {
		t.Fatalf("login without a KEK exited 0")
	}
	if !strings.Contains(errBuf.String(), "Encryption key") {
		t.Errorf("stderr = %q, want the secret_missing message", errBuf.String())
	}
}

// TestLoginCommandRefusesAPIKeyProvider proves the CLI points API-key
// providers at `provider add-key` instead of a browser grant.
func TestLoginCommandRefusesAPIKeyProvider(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "test-only-client-secret-not-real")

	var out, errBuf strings.Builder
	code := executeWith(&errBuf, &out, []string{"login", "z.ai", "--code", "x", "--config", cfg})
	if code == 0 {
		t.Fatalf("login on an API-key provider exited 0")
	}
	if !strings.Contains(errBuf.String(), "add-key") {
		t.Errorf("stderr = %q, want the add-key hint", errBuf.String())
	}
}

// TestLoginStatusRenderExpired covers the pure renderer's expired branch.
func TestLoginStatusRenderExpired(t *testing.T) {
	var out strings.Builder
	st := app.LoginStatus{
		Provider: "antigravity", LoggedIn: true, CredentialID: "oauth-x",
		Label: "dev@example.com", Email: "dev@example.com",
		Project: "proj-1", Plan: "std", ExpiresAt: time.Now().Add(-time.Hour), Expired: true,
	}
	if err := renderLoginStatus(&out, st); err != nil {
		t.Fatalf("renderLoginStatus: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "state=expired") || !strings.Contains(got, "project=proj-1") {
		t.Errorf("render = %q, want the expired state row", got)
	}
}

// TestRenderLoginStatusLoggedOutFallback covers the renderer's default reason.
func TestRenderLoginStatusLoggedOutFallback(t *testing.T) {
	var out strings.Builder
	if err := renderLoginStatus(&out, app.LoginStatus{Provider: "antigravity"}); err != nil {
		t.Fatalf("renderLoginStatus: %v", err)
	}
	if !strings.Contains(out.String(), "reason=logged-out") {
		t.Errorf("render = %q, want the default reason", out.String())
	}
}

// writeFailAfter fails on the n-th Write, so each output branch of the login
// command is reachable one at a time.
type writeFailAfter struct {
	n     int
	calls int
	mu    *sync.Mutex
}

func (w *writeFailAfter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.calls == w.n {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

// TestLoginCommandWriteErrors drives each write-error branch of the login RunE
// (risk notice, authorization URL, code hint, result line) with a writer that
// fails on a chosen write. The command runs via RunE directly (the house
// pattern for write-error branches), so args carry no command name.
func TestLoginCommandWriteErrors(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	for _, n := range []int{1, 2, 3, 4} {
		t.Run("write", func(it *testing.T) {
			cfg := installLoginSeam(it, &cliFakeGoogle{}, "test-only-client-secret-not-real")
			cmd := newLoginCmd()
			w := &writeFailAfter{n: n, mu: &sync.Mutex{}}
			cmd.SetOut(w)
			cmd.SetErr(&strings.Builder{})
			if err := cmd.Flags().Set("config", cfg); err != nil {
				it.Fatalf("set: %v", err)
			}
			if err := cmd.Flags().Set("code", "auth-code-1"); err != nil {
				it.Fatalf("set: %v", err)
			}
			if err := cmd.RunE(cmd, []string{"antigravity"}); err == nil {
				it.Fatalf("write %d: command succeeded despite the failing writer", n)
			}
		})
	}
}

// TestLoginCommandBuildError covers the boot-failure branch of the login RunE.
func TestLoginCommandBuildError(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	original := buildReadOnly
	buildReadOnly = func(string) (*app.App, error) {
		return nil, os.ErrPermission
	}
	t.Cleanup(func() { buildReadOnly = original })

	var out, errBuf strings.Builder
	if code := executeWith(&errBuf, &out, []string{"login", "antigravity", "--config", "irrelevant"}); code == 0 {
		t.Fatal("login succeeded despite the boot failure")
	}
}

// TestLoginCommandExchangeError covers the Complete-error branch of the login
// RunE: the provider refuses the code.
func TestLoginCommandExchangeError(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "test-only-client-secret-not-real")

	var out, errBuf strings.Builder
	if code := executeWith(&errBuf, &out, []string{"login", "antigravity", "--code", "wrong-code", "--config", cfg}); code == 0 {
		t.Fatal("login with a refused code exited 0")
	}
	if strings.Contains(out.String(), "provider=antigravity") {
		t.Fatal("a failed exchange still printed the identity line")
	}
}

// TestLoginStatusCommandUnknownProvider covers the status error branch for an
// unknown provider.
func TestLoginStatusCommandUnknownProvider(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	cfg := installLoginSeam(t, &cliFakeGoogle{}, "test-only-client-secret-not-real")

	var out, errBuf strings.Builder
	if code := executeWith(&errBuf, &out, []string{"login", "nope", "--status", "--config", cfg}); code == 0 {
		t.Fatal("status for an unknown provider exited 0")
	}
	if !strings.Contains(errBuf.String(), "provider.not_found") && !strings.Contains(errBuf.String(), "Unknown provider") {
		t.Errorf("stderr = %q, want the not-found message", errBuf.String())
	}
}
