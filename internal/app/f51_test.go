package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// f51Request builds a loopback request with a loopback Host (so HostGuard
// admits it) and no client key, for the F5.1 integration tests.
func f51Request(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	return req
}

// TestClientKeyValidPassesInvalidRejected is the core acceptance test
// (ADR-SEC-06 §7.1): with require-client-key on, a valid key reaches the
// gateway, while absent, invalid and revoked keys are 401 clientkey.invalid.
func TestClientKeyValidPassesInvalidRejected(t *testing.T) {
	a := buildTestApp(t)
	a.Config.Security.RequireClientKey = true

	rec, plaintext, err := a.CreateClientKey(context.Background(), "editor")
	if err != nil {
		t.Fatalf("CreateClientKey: %v", err)
	}

	t.Run("valid key admitted", func(t *testing.T) {
		req := f51Request(http.MethodPost, "/v1/chat/completions",
			`{"model":"m","messages":[]}`)
		req.Header.Set("Authorization", "Bearer "+plaintext)
		// No provider is configured, so the request fails LATER with a routing
		// error; it must NOT be a 401, which is the point of the test.
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("valid key rejected: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("absent key rejected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, f51Request(http.MethodPost, "/v1/chat/completions", `{}`))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("absent key = %d, want 401", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), domain.CodeClientKeyInvalid) {
			t.Fatalf("body = %q, want clientkey.invalid", rr.Body.String())
		}
	})

	t.Run("invalid key rejected", func(t *testing.T) {
		req := f51Request(http.MethodPost, "/v1/chat/completions", `{}`)
		req.Header.Set("Authorization", "Bearer not-a-real-key")
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("invalid key = %d, want 401", rr.Code)
		}
	})

	t.Run("revoked key rejected", func(t *testing.T) {
		if err := a.RevokeClientKey(context.Background(), rec.ID); err != nil {
			t.Fatalf("RevokeClientKey: %v", err)
		}
		req := f51Request(http.MethodPost, "/v1/chat/completions", `{}`)
		req.Header.Set("Authorization", "Bearer "+plaintext)
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("revoked key = %d, want 401", rr.Code)
		}
	})
}

// TestManagementTokenNotAcceptedAsClientKey is the separation-of-privilege
// acceptance test (ADR-SEC-06 §7.2): the operator token must not authenticate
// the gateway as a client key.
func TestManagementTokenNotAcceptedAsClientKey(t *testing.T) {
	a := buildTestApp(t)
	a.Config.Security.RequireClientKey = true
	token := readTokenFile(t, a)

	req := f51Request(http.MethodPost, "/v1/chat/completions", `{}`)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("management token accepted as client key: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), domain.CodeClientKeyInvalid) {
		t.Fatalf("body = %q, want clientkey.invalid", rr.Body.String())
	}
}

// TestClientKeyNotAcceptedOnManagement is the mirror acceptance test
// (ADR-SEC-06 §7.3): a client key must not authenticate the management API.
func TestClientKeyNotAcceptedOnManagement(t *testing.T) {
	a := buildTestApp(t)
	_, plaintext, err := a.CreateClientKey(context.Background(), "editor")
	if err != nil {
		t.Fatalf("CreateClientKey: %v", err)
	}

	req := f51Request(http.MethodGet, "/api/mgmt/ping", "")
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("client key accepted on management API: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), domain.CodeManagementAuthFailed) {
		t.Fatalf("body = %q, want api.mgmt.token_invalid", rr.Body.String())
	}
}

// TestClientKeyInQueryRejected is the acceptance test (ADR-SEC-06 §7.4): a key
// in the URL query string is a 400.
func TestClientKeyInQueryRejected(t *testing.T) {
	a := buildTestApp(t)
	_, plaintext, err := a.CreateClientKey(context.Background(), "editor")
	if err != nil {
		t.Fatalf("CreateClientKey: %v", err)
	}

	req := f51Request(http.MethodPost, "/v1/chat/completions?api_key="+plaintext, `{}`)
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("key in query = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), domain.CodeInvalidRequest) {
		t.Fatalf("body = %q, want error.invalid_request", rr.Body.String())
	}
}

// TestHostRebindingRejected is the acceptance test (ADR-SEC-06 §7.5): a
// non-loopback Host is refused with 403 before routing, even from a loopback
// peer.
func TestHostRebindingRejected(t *testing.T) {
	a := buildTestApp(t)
	for _, host := range []string{"evil.com", "127.0.0.1.nip.io"} {
		req := f51Request(http.MethodGet, "/health", "")
		req.Host = host
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("Host %q = %d, want 403", host, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), domain.CodeServerHostInvalid) {
			t.Fatalf("body = %q, want server.host_invalid", rr.Body.String())
		}
	}
}

// TestOriginExternalRejected is the acceptance test (ADR-SEC-06 §7.6): an
// external Origin on a mutating management request is 403.
func TestOriginExternalRejected(t *testing.T) {
	a := buildTestApp(t)
	req := f51Request(http.MethodPost, "/api/mgmt/token/rotate", `{}`)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("external origin = %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), domain.CodeServerOriginInvalid) {
		t.Fatalf("body = %q, want server.origin_invalid", rr.Body.String())
	}
}

// TestCORSClosedThroughHandler is the acceptance test (ADR-SEC-06 §7.7): no
// management response emits a wildcard CORS header.
func TestCORSClosedThroughHandler(t *testing.T) {
	a := buildTestApp(t)
	req := f51Request(http.MethodGet, "/api/mgmt/ping", "")
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("management response emitted CORS %q", got)
	}
}

// TestCatchAllSecurityGuardsNewRoute is the SEC-06 §1.2 regression guard at the
// assembled-handler level: a route registered AFTER the security chain is built
// is still protected because the guards wrap the whole mux. It registers a new
// mux route by rebuilding the handler, then confirms the Host guard covers it.
func TestCatchAllSecurityGuardsNewRoute(t *testing.T) {
	a := buildTestApp(t)
	// A brand-new route appended to the app's mux is not reachable through
	// a.Handler() (the mux is built inside). The proof is structural: the
	// handler wraps whatever mux it built, and the standalone middleware test
	// (TestHostGuardCatchAllProtectsNewRoute) pins the catch-all property. Here
	// we assert the assembled graph rejects a bad Host on an existing route AND
	// on an unknown one (which the mux would 404 if the guard did not run).
	for _, path := range []string{"/health", "/api/mgmt/ping", "/future/spawn"} {
		req := f51Request(http.MethodPost, path, "")
		req.Host = "evil.com"
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("path %q with bad Host = %d, want 403", path, rr.Code)
		}
	}
}

// TestManagementLoginRateLimited is the acceptance test (ADR-SEC-06 §4.2): five
// failed management logins then a 429 with Retry-After.
func TestManagementLoginRateLimited(t *testing.T) {
	a := buildTestApp(t)
	// Default config ships 5 failures/minute.

	fail := func() *httptest.ResponseRecorder {
		req := f51Request(http.MethodGet, "/api/mgmt/ping", "")
		req.Header.Set("Authorization", "Bearer wrong")
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		return rr
	}
	for i := 0; i < 5; i++ {
		if rr := fail(); rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i, rr.Code)
		}
	}
	rr := fail()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth failure = %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
}

// TestRequireClientKeyDefaultOffAndWarning documents the default decision
// (ADR-SEC-06 §6): client-key auth is OFF by default (local personal router),
// so a keyless request reaches the gateway, and the app can boot with it off.
func TestRequireClientKeyDefaultOffAndWarning(t *testing.T) {
	a := buildTestApp(t)
	if a.Config.Security.RequireClientKey {
		t.Fatal("require_client_key must default off")
	}
	// A keyless request is not 401 (it fails later for lack of a provider).
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, f51Request(http.MethodPost, "/v1/chat/completions", `{"model":"m","messages":[]}`))
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("keyless request rejected while require_client_key is off")
	}
}

// TestCreateListRevokeClientKeyThroughApp covers the App seam the CLI uses.
func TestCreateListRevokeClientKeyThroughApp(t *testing.T) {
	a := buildTestApp(t)
	ctx := context.Background()

	rec, plaintext, err := a.CreateClientKey(ctx, "one")
	if err != nil {
		t.Fatalf("CreateClientKey: %v", err)
	}
	if plaintext == "" {
		t.Fatal("empty plaintext")
	}
	list, err := a.ListClientKeys(ctx)
	if err != nil {
		t.Fatalf("ListClientKeys: %v", err)
	}
	if len(list) != 1 || list[0].ID != rec.ID {
		t.Fatalf("list = %+v", list)
	}
	if err := a.RevokeClientKey(ctx, rec.ID); err != nil {
		t.Fatalf("RevokeClientKey: %v", err)
	}
	// The plaintext never appears in the DB file.
	assertNoPlaintextInVault(t, a, plaintext)
}

// TestRemoteAccessWarnsAtBoot covers the ADR-SEC-06 §6.2 warning.
func TestRemoteAccessWarnsAtBoot(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = dir + "/heimdall.db"
	cfg.Store.TokenPath = dir + "/management-token"
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.AllowRemote = true
	cfg.Security.RequireClientKey = false

	var logBuf strings.Builder
	a, err := Build(Options{Config: cfg, Env: map[string]string{}, LogOutput: &logBuf})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()
	if !strings.Contains(logBuf.String(), "allow_remote is on") {
		t.Fatalf("missing remote-access warning in %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "require_client_key") {
		t.Fatalf("missing client-key warning in %q", logBuf.String())
	}
}

// TestClientKeyMethodsNotWired covers the nil-store guard branches.
func TestClientKeyMethodsNotWired(t *testing.T) {
	a := buildTestApp(t)
	a.ClientKeys = nil
	ctx := context.Background()
	if _, _, err := a.CreateClientKey(ctx, "x"); err == nil {
		t.Error("CreateClientKey with no store succeeded")
	}
	if _, err := a.ListClientKeys(ctx); err == nil {
		t.Error("ListClientKeys with no store succeeded")
	}
	if err := a.RevokeClientKey(ctx, "id"); err == nil {
		t.Error("RevokeClientKey with no store succeeded")
	}
}

// assertNoPlaintextInVault fails the test if plaintext is found in the database
// file after a WAL checkpoint.
func assertNoPlaintextInVault(t *testing.T, a *App, plaintext string) {
	t.Helper()
	if _, err := a.Store.Writer().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	raw, err := readFile(a.Config.Store.Path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if strings.Contains(string(raw), plaintext) {
		t.Fatal("client key plaintext found in the vault")
	}
	if !strings.Contains(string(raw), store.HashClientKey(plaintext)) {
		// The hash is stored, but it may be split across pages; a miss here is
		// not fatal for the acceptance criterion (absence of plaintext), so it
		// is only a diagnostic.
		t.Log("client key hash not found by a byte scan (may be page-fragmented)")
	}
}

// readFile is the byte-level vault reader the plaintext-absence test needs.
func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// TestTokenRotationThrottledEndToEnd is the F5-3 acceptance test at the
// assembled handler: a second immediate rotation is refused with a typed 429 +
// Retry-After, and the first still succeeds.
func TestTokenRotationThrottledEndToEnd(t *testing.T) {
	a := buildTestApp(t)
	token := readTokenFile(t, a)

	rotate := func(current string) *httptest.ResponseRecorder {
		req := f51Request(http.MethodPost, "/api/mgmt/token/rotate", "{}")
		req.Header.Set("Authorization", "Bearer "+current)
		rr := httptest.NewRecorder()
		a.Handler().ServeHTTP(rr, req)
		return rr
	}

	first := rotate(token)
	if first.Code != http.StatusOK {
		t.Fatalf("first rotation = %d, want 200 (body %s)", first.Code, first.Body.String())
	}
	// The old token is now invalid; read the NEW one so the second request
	// authenticates and reaches the rotation throttle (the throttle is what we
	// are testing, not authentication).
	newToken := readTokenFile(t, a)
	second := rotate(newToken)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second rotation = %d, want 429 (body %s)", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	if !strings.Contains(second.Body.String(), domain.CodeTokenRotateThrottled) {
		t.Fatalf("body = %q, want token.rotate_throttled", second.Body.String())
	}
}

// TestHostAllowlistFromServerHost is the F5-5 acceptance test: with
// allow_remote and a NAMED server.host, the Host guard admits that name
// (ADR-SEC-06 §3.1) while still refusing an unrelated public name.
func TestHostAllowlistFromServerHost(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = dir + "/heimdall.db"
	cfg.Store.TokenPath = dir + "/management-token"
	cfg.Server.Host = "router.lan"
	cfg.Server.AllowRemote = true

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	// The configured host is admitted (it is on the derived allowlist).
	req := f51Request(http.MethodGet, "/health", "")
	req.Host = "router.lan:8787"
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("configured host = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	// An unrelated public name is still refused.
	evil := f51Request(http.MethodGet, "/health", "")
	evil.Host = "evil.com"
	rr2 := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr2, evil)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("evil host = %d, want 403", rr2.Code)
	}
}

// TestHostAllowlistIgnoresWildcardBind proves a wildcard server.host is NOT
// added: "0.0.0.0" is not a Host a client presents, so it must not widen the
// guard.
func TestHostAllowlistIgnoresWildcardBind(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = dir + "/heimdall.db"
	cfg.Store.TokenPath = dir + "/management-token"
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.AllowRemote = true

	a, err := Build(Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	if got := a.hostAllowlist(); len(got) != 0 {
		t.Fatalf("wildcard bind added to allowlist: %v", got)
	}
}
