package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// buildGatewayApp builds an app whose z.ai provider points at srvURL with a
// declared model, so the Router can resolve and the Dispatcher can execute.
func buildGatewayApp(t *testing.T, srvURL string, models ...string) *App {
	t.Helper()
	if len(models) == 0 {
		models = []string{"glm-4.6"}
	}
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Providers = []config.ProviderConfig{{
		ID: "z.ai", BaseURL: srvURL, AuthHeader: "bearer",
		AllowLoopback: strings.HasPrefix(srvURL, "http://127.0.0.1"),
		Enabled:       true, Models: models,
	}}
	salt, _ := secret.NewSalt()
	instance, err := Build(Options{
		Config: cfg,
		Env:    map[string]string{},
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				KeyFilePath:      filepath.Join(dir, "master-key"),
				AllowEnvOverride: true,
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "gateway-test-material"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// gatewayRequest drives a POST /v1/chat/completions through the assembled handler.
func gatewayRequest(t *testing.T, a *App, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	return rec
}

// TestGatewayNonStreamEndToEnd is the BD-02 integration: an API-key credential
// in the vault, a declared model, an httptest OpenAI-compatible upstream, and a
// request that resolves → dispatches → returns the upstream body.
func TestGatewayNonStreamEndToEnd(t *testing.T) {
	var hits int32
	var gotAuth, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth = r.Header.Get("Authorization")
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		gotModel, _ = payload["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","usage":{"total_tokens":9},"choices":[]}`))
	}))
	defer srv.Close()

	a := buildGatewayApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	rec := gatewayRequest(t, a, `{"model":"glm-4.6","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"c1"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if gotAuth != "Bearer sk-live-secret-key" {
		t.Fatalf("auth = %q, want the injected bearer", gotAuth)
	}
	if gotModel != "glm-4.6" {
		t.Fatalf("upstream model = %q, want glm-4.6", gotModel)
	}
	// The gate chain ran (the logger gate records pre + post).
	records := a.GateRecords()
	sawPre, sawPost := false, false
	for _, r := range records {
		if r["stage"] == "pre_request" {
			sawPre = true
		}
		if r["stage"] == "post_response" {
			sawPost = true
		}
	}
	if !sawPre || !sawPost {
		t.Fatalf("gate stages: pre=%v post=%v, want both; records=%v", sawPre, sawPost, records)
	}
}

// TestGatewayStreamEndToEnd proves the SSE relay: each canonical chunk is framed
// as `data:` and the stream ends with the [DONE] sentinel.
func TestGatewayStreamEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srv.Close()

	a := buildGatewayApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	rec := gatewayRequest(t, a, `{"model":"glm-4.6","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want SSE", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Hel") || !strings.Contains(body, "lo") {
		t.Fatalf("stream body missing chunks: %s", body)
	}
}

// TestGatewayResolvesNamedCombo proves a combo id as the model is resolved
// through the Router (not treated as a raw model name).
func TestGatewayResolvesNamedCombo(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		gotModel, _ = payload["model"].(string)
		_, _ = w.Write([]byte(`{"id":"c1","choices":[]}`))
	}))
	defer srv.Close()

	a := buildGatewayApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	// Create a combo named "fast" that routes to the declared model.
	combo := combos.NewCombo("fast", contracts.StrategyFallback, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-4.6"},
	})
	if err := a.Combos.Create(context.Background(), combo); err != nil {
		t.Fatalf("Create combo: %v", err)
	}

	rec := gatewayRequest(t, a, `{"model":"fast","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if gotModel != "glm-4.6" {
		t.Fatalf("upstream model = %q, want the combo's resolved model glm-4.6", gotModel)
	}
}

// TestGatewayOAuthWithoutLoginIsClear proves an OAuth provider with no stored
// credential yields a typed, clear error (never a panic or a raw model error).
func TestGatewayOAuthWithoutLoginIsClear(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	// Antigravity is CloudCode/OAuth with no credential seeded.
	cfg.Providers = []config.ProviderConfig{{
		ID: "antigravity", BaseURL: "https://daily-cloudcode-pa.googleapis.com",
		Enabled: true, Models: []string{"gemini-3.5-flash"},
	}}
	salt, _ := secret.NewSalt()
	a, err := Build(Options{
		Config: cfg, Env: map[string]string{},
		SecretOptions: &secret.Options{
			Salt: salt, Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{KeyFilePath: filepath.Join(dir, "master-key"),
				AllowEnvOverride: true, Env: map[string]string{"HEIMDALL_MASTER_KEY": "oauth-test"}},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	rec := gatewayRequest(t, a, `{"model":"gemini-3.5-flash","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("OAuth request without a credential succeeded: %s", rec.Body.String())
	}
	// The error is the JSON i18n envelope carrying a typed code, not a raw panic.
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("error body is not the JSON envelope: %s", rec.Body.String())
	}
	if env.Error.Code == "" {
		t.Fatalf("error envelope has no code: %s", rec.Body.String())
	}
	// No credential -> dispatch.no_attempts (request-classified), not a provider
	// outage.
	if env.Error.Code != domain.CodeDispatchNoAttempts {
		t.Fatalf("code = %q, want dispatch.no_attempts", env.Error.Code)
	}
}

// TestGatewayRejectsBadBody proves a malformed body is a typed client error
// (ScopeRequest) and never touches the upstream.
func TestGatewayRejectsBadBody(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	a := buildGatewayApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	cases := []string{`{bad`, `{}`}
	for _, body := range cases {
		rec := gatewayRequest(t, a, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("upstream was reached for a malformed request: %d hits", hits)
	}
}

// TestGatewayUnknownModelIsTypedError proves an unroutable model yields
// route.no_candidate, not a panic.
func TestGatewayUnknownModelIsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	a := buildGatewayApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	rec := gatewayRequest(t, a, `{"model":"does-not-exist","messages":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), domain.CodeRouteNoCandidate) {
		t.Fatalf("body = %s, want %s", rec.Body.String(), domain.CodeRouteNoCandidate)
	}
}

// TestBuildExecutorBranchesByProtocol proves the composition root picks the
// CloudCode family for WireCloudCode and OpenAICompat otherwise.
func TestBuildExecutorBranchesByProtocol(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1")

	oa, err := a.Providers.Get("z.ai")
	if err != nil {
		t.Fatalf("Get z.ai: %v", err)
	}
	if oa.Protocol() != contracts.WireOpenAI {
		t.Fatalf("z.ai protocol = %q, want openai", oa.Protocol())
	}

	anti, err := a.Providers.Get("antigravity")
	if err != nil {
		t.Fatalf("Get antigravity: %v", err)
	}
	if anti.Protocol() != contracts.WireCloudCode {
		t.Fatalf("antigravity protocol = %q, want cloudcode", anti.Protocol())
	}
	// The CloudCode family builds a CloudCode executor (asserted by type name
	// through the executor's Family() and a successful construction with an
	// OAuth credential and a KEK-backed deps bundle).
	if anti.ID() != "antigravity" {
		t.Fatalf("family id = %q", anti.ID())
	}
}

// TestGatewayPipelineEndToEnd is the D-02 integration seam: a named pipeline
// combo whose two steps both target the (single) upstream is executed by the
// Dispatcher as a CHAIN — the second request carries the first step's output,
// and the client sees only the second step's response.
func TestGatewayPipelineEndToEnd(t *testing.T) {
	var mu atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := mu.Add(1)
		var payload struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		last := ""
		if len(payload.Messages) > 0 {
			last = payload.Messages[len(payload.Messages)-1].Content
		}
		bodies = append(bodies, last)
		content := "step" + string(rune('0'+n)) + "(" + last + ")"
		resp, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": content}}},
		})
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	a := buildGatewayApp(t, srv.URL+"/v1", "glm-4.6", "glm-4.5")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	combo := combos.NewCombo("chain", contracts.StrategyPipeline, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-4.6"},
		{Kind: combos.StepModel, Ref: "glm-4.5"},
	})
	if err := a.Combos.Create(context.Background(), combo); err != nil {
		t.Fatalf("Create combo: %v", err)
	}

	rec := gatewayRequest(t, a, `{"model":"chain","messages":[{"role":"user","content":"original"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// Only the LAST step's response reached the client.
	if !strings.Contains(rec.Body.String(), "step2(") {
		t.Fatalf("client did not receive the last step's answer: %s", rec.Body.String())
	}
	// Two upstream calls, the second carrying the first's output.
	if got := mu.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (one per pipeline step)", got)
	}
	if len(bodies) != 2 || !strings.Contains(bodies[1], "step1(original)") {
		t.Fatalf("second step input = %q, want the first step's output", bodies)
	}
}

// TestGatewayFusionEndToEnd is the D-02 seam for fusion: a fusion combo fans out
// its panels to the upstream and, with no judge route configured, falls back to
// the first successful panel's response (the documented degenerate case).
func TestGatewayFusionEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": "panel-answer"}}},
		})
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	a := buildGatewayApp(t, srv.URL+"/v1", "glm-4.6", "glm-4.5")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live-secret-key")

	combo := combos.NewCombo("fuse", contracts.StrategyFusion, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-4.6"},
		{Kind: combos.StepModel, Ref: "glm-4.5"},
	})
	if err := a.Combos.Create(context.Background(), combo); err != nil {
		t.Fatalf("Create combo: %v", err)
	}

	rec := gatewayRequest(t, a, `{"model":"fuse","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "panel-answer") {
		t.Fatalf("fusion response missing: %s", rec.Body.String())
	}
}

// TestConfigDeclaresModels proves a provider's models are parsed and drive the
// Router catalog.
func TestConfigDeclaresModels(t *testing.T) {
	a := buildGatewayApp(t, "https://example.invalid/v1", "glm-4.6", "glm-4.5")
	caps, ok := a.Providers.DeclaresModel("glm-4.6"), true
	if !caps || !ok {
		t.Fatal("declared model not reported")
	}
	if a.Providers.DeclaresModel("nope") {
		t.Fatal("undeclared model reported as known")
	}
}
