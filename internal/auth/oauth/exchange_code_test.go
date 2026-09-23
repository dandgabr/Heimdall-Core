package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// antigravityPostServer serves the userinfo/loadCodeAssist/onboardUser triple
// the Antigravity post-exchange calls after any successful grant.
func antigravityPostServer(t *testing.T, onboarded *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sub-1", "email": "u@example.com"})
		case r.URL.Path == "/loadCodeAssist":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cloudaicompanionProject": map[string]any{"id": "proj-xyz"},
				"allowedTiers":            []map[string]any{{"id": "std-tier", "isDefault": true}},
			})
		case r.URL.Path == "/onboardUser":
			if onboarded != nil {
				atomic.AddInt32(onboarded, 1)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
		default:
			t.Errorf("unexpected post-exchange path %q", r.URL.Path)
		}
	}))
}

// antigravityTokenServer serves the authorization_code token exchange and
// records the posted form, so the test can assert the client secret and the
// PKCE verifier travelled.
func antigravityTokenServer(t *testing.T, lastForm *url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if lastForm != nil {
			*lastForm = r.PostForm
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT-1", "refresh_token": "RT-1", "expires_in": 3600})
	}))
}

// TestAntigravityExchangeCodePastedPath proves the paste-code fallback runs the
// full grant: the code is exchanged with the client secret and the PKCE
// verifier, and the result is enriched by the same post-exchange as the
// callback path (BD-02 §1).
func TestAntigravityExchangeCodePastedPath(t *testing.T) {
	var lastForm url.Values
	var onboarded int32
	tokenSrv := antigravityTokenServer(t, &lastForm)
	defer tokenSrv.Close()
	postSrv := antigravityPostServer(t, &onboarded)
	defer postSrv.Close()

	desc := antigravityDesc()
	desc.TokenEndpoint = tokenSrv.URL
	cfg := AntigravityConfig{
		UserInfoEndpoint:       postSrv.URL + "/userinfo",
		LoadCodeAssistEndpoint: postSrv.URL + "/loadCodeAssist",
		OnboardUserEndpoint:    postSrv.URL + "/onboardUser",
		OnboardAttempts:        1,
	}
	flow := NewAntigravityFlow(testDeps(), desc, cfg)

	ch, err := flow.Begin(context.Background(), desc)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// The pasted path must not need the browser: close the listener up front,
	// exactly as the caller does.
	if err := flow.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := flow.ExchangeCode(context.Background(), ch, "pasted-code-1", desc)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if res.Access.IsEmpty() || res.Access.Reveal() != "AT-1" {
		t.Fatalf("access = %v, want AT-1", res.Access)
	}
	if res.Token.Token.Reveal() != "RT-1" || !res.Token.Rotated {
		t.Fatalf("refresh = %v rotated=%v, want RT-1/true", res.Token.Token, res.Token.Rotated)
	}
	if res.Account.Email != "u@example.com" || res.Account.Project != "proj-xyz" || res.Account.Plan != "std-tier" {
		t.Fatalf("account = %+v, want the enriched identity", res.Account)
	}
	if got := lastForm.Get("client_secret"); got != "client-secret" {
		t.Errorf("client_secret = %q, want the descriptor value", got)
	}
	if got := lastForm.Get("code_verifier"); got == "" || got != ch.PKCEVerifier.Reveal() {
		t.Errorf("code_verifier = %q, want the challenge verifier", got)
	}
	if got := lastForm.Get("code"); got != "pasted-code-1" {
		t.Errorf("code = %q, want the pasted code", got)
	}
}

// TestExchangeCodeRefusesIncomplete proves the paste-code path fails closed on
// a codeless call and on a challenge missing its PKCE material.
func TestExchangeCodeRefusesIncomplete(t *testing.T) {
	desc := antigravityDesc()
	desc.TokenEndpoint = "https://token.example" // never reached
	flow := NewPKCEFlow(testDeps(), desc)

	if _, err := flow.ExchangeCode(context.Background(),
		contracts.AuthChallenge{State: "s", PKCEVerifier: contracts.Secret("v"), RedirectURI: "http://127.0.0.1/callback"},
		"", desc); !hasOAuthCode(err, domain.CodeAuthStateMismatch) {
		t.Fatalf("empty code err = %v, want %s", err, domain.CodeAuthStateMismatch)
	}
	if _, err := flow.ExchangeCode(context.Background(),
		contracts.AuthChallenge{State: "s", RedirectURI: "http://127.0.0.1/callback"},
		"code", desc); !hasOAuthCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("verifier-less challenge err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// TestAntigravityExchangeCodeErrorPropagation proves the Antigravity wrapper
// propagates the PKCE exchange error instead of running a post-exchange on an
// empty result.
func TestAntigravityExchangeCodeErrorPropagation(t *testing.T) {
	flow := NewAntigravityFlow(testDeps(), antigravityDesc(), AntigravityConfig{})
	_, err := flow.ExchangeCode(context.Background(), contracts.AuthChallenge{State: "s"}, "code", antigravityDesc())
	if !hasOAuthCode(err, domain.CodeAuthFlowInsecure) {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthFlowInsecure)
	}
}

// hasOAuthCode is the package-local DomainError code check.
func hasOAuthCode(err error, code string) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == code
}
