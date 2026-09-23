package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/observability"
)

// TestClientKeyFromContext pins the F5 contract: the client identity the
// gateway hands to the gates comes from the AUTHENTICATED context the
// client-key middleware populated, never from a request header. An absent
// identity yields "" — no invented value.
func TestClientKeyFromContext(t *testing.T) {
	if got := ClientKeyFromContext(&http.Request{}); got != "" {
		t.Fatalf("no context = %q, want empty", got)
	}
	if got := ClientKeyFromContext(nil); got != "" {
		t.Fatalf("nil request = %q, want empty", got)
	}

	req := (&http.Request{}).WithContext(
		observability.WithClientID(context.Background(), domain.ClientID("client-abc")))
	if got := ClientKeyFromContext(req); got != "client-abc" {
		t.Fatalf("authenticated context = %q, want client-abc", got)
	}
}

// TestChatPropagatesAuthenticatedClientKeyToGateInput proves the boundary hands
// the AUTHENTICATED identity (from the request context) to the chain's Meta —
// the stateful gates' key source — and leaves the key ABSENT when the request
// carries no authenticated identity.
func TestChatPropagatesAuthenticatedClientKeyToGateInput(t *testing.T) {
	cases := []struct {
		name        string
		clientID    string
		wantPresent bool
	}{
		{"authenticated identity propagates", "client-1", true},
		{"no authentication stays absent", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue}}
			h := newHandler(&fakeResolver{plan: samplePlan()}, &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}, nil, chain)
			chatWithClientID(h, tc.clientID)

			got, present := chain.preMeta[ClientKeyMeta]
			if present != tc.wantPresent {
				t.Fatalf("present = %v, want %v", present, tc.wantPresent)
			}
			if present && got != tc.clientID {
				t.Fatalf("key = %q, want %q", got, tc.clientID)
			}
		})
	}
}

// TestChatIgnoresUnverifiedClientHeader proves the raw header no longer keys
// the gates: with no authenticated context, a presented Authorization header
// must not surface as the Meta client key. This is the G-1 regression guard.
func TestChatIgnoresUnverifiedClientHeader(t *testing.T) {
	chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue}}
	h := newHandler(&fakeResolver{plan: samplePlan()}, &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}, nil, chain)

	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	req.Header.Set("Authorization", "Bearer sk-unverified")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if _, present := chain.preMeta[ClientKeyMeta]; present {
		t.Fatal("an unverified header must not populate the client.key meta")
	}
}

// chatWithClientID drives a chat request whose context carries an authenticated
// client identity (or none when clientID is empty).
func chatWithClientID(h *Handler, clientID string) {
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	if clientID != "" {
		req = req.WithContext(observability.WithClientID(req.Context(), domain.ClientID(clientID)))
	}
	mux.ServeHTTP(httptest.NewRecorder(), req)
}
