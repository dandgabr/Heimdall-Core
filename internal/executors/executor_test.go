package executors

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
)

// --- fakes ---

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{}

func (fakeIDs) NewRequestID() domain.RequestID { return "req" }

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

// fakeEgress returns a client whose transport is supplied by the test.
type fakeEgress struct{ doer contracts.HTTPDoer }

func (f fakeEgress) Client(contracts.EgressSpec) (contracts.HTTPDoer, error) {
	return f.doer, nil
}

// doerFunc adapts a function to contracts.HTTPDoer.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// openerFunc adapts a function to contracts.SecretOpener.
type openerFunc func(string) ([]byte, error)

func (f openerFunc) Open(s string) ([]byte, error) { return f(s) }

func testDeps(doer contracts.HTTPDoer, secret string) contracts.ExecutorDeps {
	deps := contracts.ExecutorDeps{
		Clock:    fakeClock{t: time.Unix(1000, 0)},
		IDs:      fakeIDs{},
		Redactor: fakeRedactor{},
		Egress:   fakeEgress{doer: doer},
	}
	if secret != "" {
		deps.Secrets = openerFunc(func(string) ([]byte, error) { return []byte(secret), nil })
	}
	return deps
}

func mustExecutor(t *testing.T, cfg Config, deps contracts.ExecutorDeps) *Executor {
	t.Helper()
	e, err := New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func apiKeyCred() contracts.Credential {
	return contracts.Credential{
		ID: "c1", Provider: "z.ai", AuthMode: contracts.AuthAPIKey, Sealed: []byte("enc:v1:x:y:z"),
	}
}

// --- New / deps ---

func TestNewRejectsBadDepsAndConfig(t *testing.T) {
	if _, err := New(Config{BaseURL: "https://x"}, contracts.ExecutorDeps{}); err == nil {
		t.Error("missing deps accepted")
	}
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "")
	if _, err := New(Config{}, deps); err == nil {
		t.Error("empty base url accepted")
	}
}

// --- Auth ---

func TestAuthBearerAndAPIKeyHeader(t *testing.T) {
	tests := []struct {
		name  string
		style AuthHeaderStyle
		field string
		want  string
	}{
		{"bearer", AuthBearer, "Authorization", "Bearer SECRET-KEY"},
		{"api-key header", AuthAPIKeyHeader, "x-api-key", "SECRET-KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			doer := doerFunc(func(r *http.Request) (*http.Response, error) {
				got = r.Header.Get(tt.field)
				return okJSONResponse(), nil
			})
			e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1", AuthStyle: tt.style}, testDeps(doer, "SECRET-KEY"))
			if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred()); err != nil {
				t.Fatalf("Do: %v", err)
			}
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

// TestCallerCannotOverrideAuth proves the caller's Authorization header is
// cleared and replaced by the credential's.
func TestCallerCannotOverrideAuth(t *testing.T) {
	var got string
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Authorization")
		return okJSONResponse(), nil
	})
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "REAL"))
	_, err := e.Do(context.Background(), contracts.WireRequest{
		Body:    []byte(`{}`),
		Headers: http.Header{"Authorization": {"Bearer ATTACKER"}},
	}, apiKeyCred())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "Bearer REAL" {
		t.Errorf("Authorization = %q, want the credential's value", got)
	}
}

func TestAuthNoneSendsNoAuth(t *testing.T) {
	var got string
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Authorization")
		return okJSONResponse(), nil
	})
	e := mustExecutor(t, Config{Family: "local", BaseURL: "http://127.0.0.1:1/v1", AllowLoopback: true}, testDeps(doer, ""))
	cred := contracts.Credential{ID: "c", Provider: "local", AuthMode: contracts.AuthNone}
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, cred); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "" {
		t.Errorf("Authorization = %q, want empty for AuthNone", got)
	}
}

func TestAuthOAuthRefused(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "s"))
	_, err := e.Do(context.Background(), contracts.WireRequest{}, contracts.Credential{AuthMode: contracts.AuthOAuth})
	if !hasCode(err, domain.CodeProviderNoExecutor) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNoExecutor)
	}
}

func TestAuthMissingSecretFailsClosed(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), ""))
	_, err := e.Do(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthSecretMissing)
	}
}

func TestAuthSecretOpenErrorFailsClosed(t *testing.T) {
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "")
	deps.Secrets = openerFunc(func(string) ([]byte, error) { return nil, errors.New("decrypt failed") })
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, deps)
	_, err := e.Do(context.Background(), contracts.WireRequest{}, apiKeyCred())
	if !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthSecretMissing)
	}
}

// --- Do ---

func TestDoReturnsCanonicalResponse(t *testing.T) {
	doer := doerFunc(func(r *http.Request) (*http.Response, error) { return okJSONResponse(), nil })
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	resp, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{"model":"m"}`)}, apiKeyCred())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusOK || !strings.Contains(string(resp.Body), "hello") {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestDoRequestBuildError(t *testing.T) {
	// A control character in the base URL makes NewRequest fail.
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "http://exa mple.test/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k"))
	_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
	if !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("err = %v, want %s", err, domain.CodeInvalidRequest)
	}
}

func TestDoOversizedResponse(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("a", 100))),
		}, nil
	})
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1", MaxResponseBytes: 16}, testDeps(doer, "k"))
	_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
	if !hasCode(err, domain.CodeUpstreamResponseTooLarge) {
		t.Fatalf("err = %v, want %s", err, domain.CodeUpstreamResponseTooLarge)
	}
}

// TestDoErrorScopeMapping is the ADR-0002 table: each upstream status maps to the
// right Scope/Retryable/HTTPStatus.
func TestDoErrorScopeMapping(t *testing.T) {
	tests := []struct {
		status     int
		wantScope  domain.ErrScope
		retryable  bool
		retryAfter time.Duration
	}{
		{http.StatusBadRequest, domain.ScopeRequest, false, 0},
		{http.StatusUnauthorized, domain.ScopeCredential, false, 0},
		{http.StatusForbidden, domain.ScopeCredential, false, 0},
		{http.StatusTooManyRequests, domain.ScopeCredential, true, 30 * time.Second},
		{http.StatusInternalServerError, domain.ScopeProvider, true, 0},
		{http.StatusBadGateway, domain.ScopeProvider, true, 0},
		{http.StatusRequestTimeout, domain.ScopeProvider, true, 0},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			doer := doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tt.status,
					Header:     http.Header{"Retry-After": {"30"}},
					Body:       io.NopCloser(strings.NewReader("upstream detail")),
				}, nil
			})
			e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
			_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
			de, ok := err.(*domain.DomainError)
			if !ok {
				t.Fatalf("err = %T, want *DomainError", err)
			}
			if de.Scope != tt.wantScope {
				t.Errorf("scope = %v, want %v", de.Scope, tt.wantScope)
			}
			if de.Retryable != tt.retryable {
				t.Errorf("retryable = %v, want %v", de.Retryable, tt.retryable)
			}
			if de.RetryAfter != tt.retryAfter {
				t.Errorf("retryAfter = %v, want %v", de.RetryAfter, tt.retryAfter)
			}
			// The upstream body must never be echoed in the error.
			if de.Params["body"] != "" || strings.Contains(de.Error(), "upstream detail") {
				t.Errorf("error echoed the upstream body: %+v", de)
			}
		})
	}
}

func TestDoTransportTimeout(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutErr{} })
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamTimeout || de.Scope != domain.ScopeProvider || !de.Retryable {
		t.Fatalf("err = %+v", err)
	}
}

func TestDoTransportUnavailable(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial refused") })
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeUpstreamUnavailable || !de.Retryable {
		t.Fatalf("err = %+v", err)
	}
}

func TestDoContextCanceled(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, context.Canceled })
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	_, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred())
	if !hasCode(err, domain.CodeUpstreamTimeout) {
		t.Fatalf("err = %v, want upstream_timeout", err)
	}
}

// --- CountTokens ---

func TestCountTokensUnavailable(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k"))
	_, err := e.CountTokens(context.Background(), contracts.WireRequest{}, "m")
	if !hasCode(err, domain.CodeProviderNoExecutor) {
		t.Fatalf("err = %v, want %s", err, domain.CodeProviderNoExecutor)
	}
}

func TestCountTokensOK(t *testing.T) {
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/count_tokens") {
			t.Errorf("path = %q", r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"input_tokens":42}`)),
		}, nil
	})
	e := mustExecutor(t, Config{
		Family: "z.ai", BaseURL: "https://x/v1", CountTokensEndpoint: "/count_tokens",
	}, testDeps(doer, "k"))
	n, err := e.CountTokens(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, "m")
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	if n != 42 {
		t.Errorf("tokens = %d, want 42", n)
	}
}

func TestCountTokensUpstreamErrorAndBadJSON(t *testing.T) {
	// Upstream non-2xx.
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("boom")),
		}, nil
	})
	e := mustExecutor(t, Config{Family: "z", BaseURL: "https://x/v1", CountTokensEndpoint: "/count_tokens"}, testDeps(doer, "k"))
	if _, err := e.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}

	// Bad JSON.
	doer2 := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{"))}, nil
	})
	e2 := mustExecutor(t, Config{Family: "z", BaseURL: "https://x/v1", CountTokensEndpoint: "/c"}, testDeps(doer2, "k"))
	if _, err := e2.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeBadUpstreamResponse) {
		t.Fatalf("err = %v", err)
	}
}

// --- remaining branch coverage (pre-existing gaps in this package) ---

// errorEgress makes Egress.Client fail, covering New's transport-build error.
type errorEgress struct{}

func (errorEgress) Client(contracts.EgressSpec) (contracts.HTTPDoer, error) {
	return nil, errors.New("egress refused")
}

func TestNewEgressClientError(t *testing.T) {
	deps := contracts.ExecutorDeps{
		Clock: fakeClock{t: time.Unix(1000, 0)}, IDs: fakeIDs{},
		Redactor: fakeRedactor{}, Egress: errorEgress{},
	}
	if _, err := New(Config{Family: "z", BaseURL: "https://x/v1"}, deps); err == nil {
		t.Fatal("expected the egress build error")
	}
}

func TestFamilyReportsID(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k"))
	if e.Family() != "z.ai" {
		t.Fatalf("Family = %q", e.Family())
	}
}

// TestAuthEmptySealedFailsClosed covers the empty-sealed-blob branch, distinct
// from the nil-Secrets branch.
func TestAuthEmptySealedFailsClosed(t *testing.T) {
	deps := testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k")
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, deps)
	cred := contracts.Credential{ID: "c", Provider: "z.ai", AuthMode: contracts.AuthAPIKey}
	if _, err := e.Do(context.Background(), contracts.WireRequest{}, cred); !hasCode(err, domain.CodeAuthSecretMissing) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthSecretMissing)
	}
}

// TestAuthUnknownModeFailsClosed covers openCredential's default arm.
func TestAuthUnknownModeFailsClosed(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "s"))
	cred := contracts.Credential{AuthMode: contracts.AuthMode(99)}
	if _, err := e.Do(context.Background(), contracts.WireRequest{}, cred); !hasCode(err, domain.CodeCredentialInvalidAuthMode) {
		t.Fatalf("err = %v, want %s", err, domain.CodeCredentialInvalidAuthMode)
	}
}

// TestDoStreamRequestSetsAccept covers the req.Stream Accept-header branch of Do.
func TestDoStreamRequestSetsAccept(t *testing.T) {
	var got string
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Accept")
		return okJSONResponse(), nil
	})
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`), Stream: true}, apiKeyCred()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "text/event-stream" {
		t.Fatalf("Accept = %q", got)
	}
}

// failingBody returns a read error, covering Do's body-read failure path.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (failingBody) Close() error             { return nil }

func TestDoBodyReadError(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}}, nil
	})
	e := mustExecutor(t, Config{Family: "z.ai", BaseURL: "https://x/v1"}, testDeps(doer, "k"))
	if _, err := e.Do(context.Background(), contracts.WireRequest{Body: []byte(`{}`)}, apiKeyCred()); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestCountTokensBuildError covers CountTokens' request-build failure.
func TestCountTokensBuildError(t *testing.T) {
	e := mustExecutor(t, Config{Family: "z", BaseURL: "http://exa mple.test/v1", CountTokensEndpoint: "/c"}, testDeps(doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), "k"))
	if _, err := e.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

// TestCountTokensTransportAndReadError covers CountTokens' transport failure and
// its body-read failure.
func TestCountTokensTransportAndReadError(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial refused") })
	e := mustExecutor(t, Config{Family: "z", BaseURL: "https://x/v1", CountTokensEndpoint: "/c"}, testDeps(doer, "k"))
	if _, err := e.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("transport err = %v", err)
	}

	doer2 := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}}, nil
	})
	e2 := mustExecutor(t, Config{Family: "z", BaseURL: "https://x/v1", CountTokensEndpoint: "/c"}, testDeps(doer2, "k"))
	if _, err := e2.CountTokens(context.Background(), contracts.WireRequest{}, "m"); !hasCode(err, domain.CodeUpstreamUnavailable) {
		t.Fatalf("read err = %v", err)
	}
}

// TestTransportErrorNil covers the nil guard.
func TestTransportErrorNil(t *testing.T) {
	if transportError(nil) != nil {
		t.Fatal("transportError(nil) should be nil")
	}
}

// TestTransportErrorPreservesEgressDenial is the P1 regression: a typed egress
// refusal wrapped by net/http in *url.Error must survive transportError with its
// code and fail-closed attributes, never become a retryable upstream_unavailable.
func TestTransportErrorPreservesEgressDenial(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"destination denied", domain.CodeUpstreamDestinationDenied},
		{"insecure url", domain.CodeUpstreamInsecureURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// net/http wraps the Control hook error in *url.Error.
			typed := domain.New(tt.code,
				domain.WithHTTPStatus(http.StatusBadGateway),
				domain.WithScope(domain.ScopeProvider),
			)
			wrapped := &url.Error{Op: "Get", URL: "https://x", Err: typed}

			got := transportError(wrapped)
			if got == nil {
				t.Fatal("transportError returned nil")
			}
			if got.Code != tt.code {
				t.Fatalf("code = %s, want %s (must not be reclassified)", got.Code, tt.code)
			}
			if got.Retryable {
				t.Fatalf("a denied destination became retryable: %+v", got)
			}
			if got.HTTPStatus != http.StatusBadGateway || got.Scope != domain.ScopeProvider {
				t.Fatalf("ADR-0002 attributes lost: %+v", got)
			}
		})
	}
}

// TestTransportErrorStillMapsGeneric covers the unchanged generic path: a plain
// transport error is still a retryable upstream_unavailable.
func TestTransportErrorStillMapsGeneric(t *testing.T) {
	de := transportError(errors.New("dial refused"))
	if de == nil || de.Code != domain.CodeUpstreamUnavailable || !de.Retryable {
		t.Fatalf("generic err = %+v", de)
	}
	if egressPolicyError(de) != nil {
		t.Fatal("a generic upstream_unavailable was mistaken for a policy denial")
	}
}

// TestNowWallClock covers the Clock==nil fallback. It builds the struct directly
// because New requires a Clock.
func TestNowWallClock(t *testing.T) {
	e := &Executor{}
	if e.now().IsZero() {
		t.Fatal("now() returned the zero time")
	}
}

// TestParseRetryAfterBranches covers all arms: delta seconds, HTTP date in the
// future, HTTP date in the past, negative delta, blank and invalid values.
func TestParseRetryAfterBranches(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if d := parseRetryAfter("30", now); d != 30*time.Second {
		t.Fatalf("delta = %v", d)
	}
	if d := parseRetryAfter(now.Add(45*time.Second).Format(http.TimeFormat), now); d != 45*time.Second {
		t.Fatalf("future date = %v", d)
	}
	if d := parseRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now); d != 0 {
		t.Fatalf("past date = %v", d)
	}
	if d := parseRetryAfter("-5", now); d != 0 {
		t.Fatalf("negative = %v", d)
	}
	if d := parseRetryAfter("   ", now); d != 0 {
		t.Fatalf("blank = %v", d)
	}
	if d := parseRetryAfter("soon", now); d != 0 {
		t.Fatalf("invalid = %v", d)
	}
}

// TestStringsTrim covers leading/trailing tabs and spaces and the all-blank arm.
func TestStringsTrim(t *testing.T) {
	if got := stringsTrim("\t x y "); got != "x y" {
		t.Fatalf("trim = %q", got)
	}
	if got := stringsTrim("   "); got != "" {
		t.Fatalf("all-blank = %q", got)
	}
}

// --- helpers ---

func okJSONResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"hello"}}]}`)),
	}
}

func hasCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// realEgressDeps builds deps whose Egress is the real policy, so the executor
// dials a live httptest server (still subject to the SSRF rules).
func realEgressDeps(secret string) contracts.ExecutorDeps {
	deps := contracts.ExecutorDeps{
		Clock:    fakeClock{t: time.Unix(1000, 0)},
		IDs:      fakeIDs{},
		Redactor: fakeRedactor{},
		Egress:   egress.New(),
	}
	if secret != "" {
		deps.Secrets = openerFunc(func(string) ([]byte, error) { return []byte(secret), nil })
	}
	return deps
}
