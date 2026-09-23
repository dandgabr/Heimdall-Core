package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// TestClientKeyFromHeaders pins the extraction contract: the presented
// identity is honoured (Bearer first, then the dedicated header), every
// malformed shape counts as ABSENT, and no invented value ever comes back.
func TestClientKeyFromHeaders(t *testing.T) {
	cases := []struct {
		name   string
		auth   string
		apiKey string
		want   string
	}{
		{"bearer", "Bearer sk-client-key-1", "", "sk-client-key-1"},
		{"bearer extra spaces", "Bearer   sk-key  ", "", "sk-key"},
		{"dedicated header", "", "sk-api-key-2", "sk-api-key-2"},
		{"no headers at all", "", "", ""},
		{"empty everything", " ", " ", ""},
		{"non-bearer scheme", "Basic dXNlcjpwYXNz", "", ""},
		{"bearer without token", "Bearer ", "", ""},
		{"bearer only scheme word", "Bearer", "", ""},
		{"bare value without scheme", "sk-raw-value", "", ""},
		{"bearer wins over dedicated", "Bearer sk-primary", "sk-fallback", "sk-primary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.auth != "" {
				h.Set("Authorization", tc.auth)
			}
			if tc.apiKey != "" {
				h.Set("X-API-Key", tc.apiKey)
			}
			if got := ClientKeyFromHeaders(h); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// chatWithHeaders drives a chat request carrying custom identity headers
// through the mounted route.
func chatWithHeaders(t *testing.T, h *Handler, auth, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestChatPropagatesClientKeyToGateInput proves the boundary hands the
// presented identity to the chain's Meta (the stateful gates' key source),
// and leaves the key ABSENT when the request presents none — no invented
// value, not even an empty string.
func TestChatPropagatesClientKeyToGateInput(t *testing.T) {
	cases := []struct {
		name        string
		auth        string
		apiKey      string
		wantPresent bool
		wantKey     string
	}{
		{"bearer key propagates", "Bearer sk-live-1", "", true, "sk-live-1"},
		{"api key propagates", "", "sk-api-2", true, "sk-api-2"},
		{"no identity stays absent", "", "", false, ""},
		{"malformed stays absent", "Basic xxx", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := &fakeChain{pre: contracts.Decision{Kind: contracts.DecisionContinue}}
			h := newHandler(&fakeResolver{plan: samplePlan()}, &fakeDispatcher{stream: &memStream{chunks: []contracts.Chunk{{Data: []byte("x")}}}}, nil, chain)
			chatWithHeaders(t, h, tc.auth, tc.apiKey)

			got, present := chain.preMeta[ClientKeyMeta]
			if present != tc.wantPresent {
				t.Fatalf("present = %v, want %v", present, tc.wantPresent)
			}
			if present && got != tc.wantKey {
				t.Fatalf("key = %q, want %q", got, tc.wantKey)
			}
		})
	}
}
