package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/gates"
)

var errBoom = errors.New("gate boom")

func TestNewObserverRejectsNilChain(t *testing.T) {
	if _, err := NewObserver(nil); err == nil {
		t.Fatal("nil chain accepted")
	}
}

func TestObserverRunsGatesAndNeverReadsBody(t *testing.T) {
	var records []map[string]string
	gate := gates.NewLogger(func(_ string, fields map[string]string) {
		records = append(records, fields)
	})
	chain, err := New([]contracts.Gate{gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observer, err := NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}

	const secret = "sk-live-BODY-AND-HEADER-MUST-NOT-LEAK"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := observer.Handler(inner)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"key":"`+secret+`"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(records) == 0 {
		t.Fatal("observer did not run the gate")
	}
	for _, r := range records {
		for k, v := range r {
			if strings.Contains(v, secret) {
				t.Fatalf("observer leaked the secret in %s=%s", k, v)
			}
		}
	}
	// The header NAME must be present; the value must not.
	found := false
	for _, r := range records {
		if strings.Contains(r["header_names"], "Authorization") {
			found = true
		}
	}
	if !found {
		t.Errorf("header names not recorded: %+v", records)
	}
}

// TestObserverScopeIsInferenceOnly is the F5-2 regression guard: the inference
// chain (its admission gates included) runs ONLY on /v1/*; management, health
// and the GUI are passed straight through, so an inference rate-limit can never
// throttle the operator's control surface.
func TestObserverScopeIsInferenceOnly(t *testing.T) {
	chain, err := New([]contracts.Gate{blockingGate{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observer, err := NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}

	called := false
	h := observer.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// Non-inference routes pass through untouched, even under a blocking gate.
	for _, path := range []string{"/api/mgmt/status", "/health", "/web/", "/"} {
		called = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !called {
			t.Errorf("path %s: status=%d called=%v, want passthrough (200)", path, rec.Code, called)
		}
	}

	// Inference is blocked by the gate (Block synthetic materialised), including
	// read-only /v1/models — the whole /v1/* surface is in scope.
	for _, path := range []string{"/v1/chat/completions", "/v1/models"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("inference path %s status = %d, want the gate synthetic 429", path, rec.Code)
		}
	}
}

// TestObserverMaterializesBlockSynthetic is the F5-2 core: a gate Block's
// SyntheticResponse is written with its OWN status and headers (429 +
// Retry-After + i18n envelope), not discarded for a plain-text 403.
func TestObserverMaterializesBlockSynthetic(t *testing.T) {
	gate := preOnly("rater", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		d := contracts.Decision{Kind: contracts.DecisionBlock, Code: domain.CodeSecurityRateLimited}
		d.Synthetic = &contracts.SyntheticResponse{
			Status:  http.StatusTooManyRequests,
			Headers: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Retry-After": []string{"7"}},
			Body:    []byte(`{"error":{"code":"security.rate_limited","params":{"retry_after":"7"}}}`),
		}
		return d, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)

	called := false
	h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "7" {
		t.Fatalf("Retry-After = %q, want 7", rec.Header().Get("Retry-After"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeSecurityRateLimited) {
		t.Fatalf("body = %q, want the rate_limited envelope", rec.Body.String())
	}
	if called {
		t.Error("inner handler ran despite a Block")
	}
}

// TestObserverBlockWithoutSyntheticIsTypedEnvelope covers the defensive branch:
// a Block with no Synthetic becomes a typed 500 envelope, never plain text.
func TestObserverBlockWithoutSyntheticIsTypedEnvelope(t *testing.T) {
	gate := preOnly("bad", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{Kind: contracts.DecisionBlock}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q, want JSON envelope", ct)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeInternal) {
		t.Fatalf("body = %q, want error.internal", rec.Body.String())
	}
}

// TestObserverSyntheticDefaultStatus covers the status==0 -> 200 default.
func TestObserverSyntheticDefaultStatus(t *testing.T) {
	gate := preOnly("cache", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		d := contracts.Decision{Kind: contracts.DecisionBlock}
		d.Synthetic = &contracts.SyntheticResponse{Body: []byte(`{"hit":true}`)}
		return d, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
}

// TestObserverRerouteIsTypedEnvelope covers the Reroute refusal: a typed JSON
// envelope, never plain text.
func TestObserverRerouteIsTypedEnvelope(t *testing.T) {
	gate := preOnly("router", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{Kind: contracts.DecisionReroute, Reroute: &contracts.RerouteTarget{Provider: "p"}}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeProviderRerouteUnsupported) {
		t.Fatalf("body = %q, want the reroute code", rec.Body.String())
	}
}

// TestObserverModifyIsDroppedAtBoundary covers the Modify branch: the observer
// has no body to rewrite, so it proceeds unchanged to the inner handler.
func TestObserverModifyIsDroppedAtBoundary(t *testing.T) {
	gate := preOnly("mod", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{Kind: contracts.DecisionModify, Body: []byte(`[]`)}, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	called := false
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v, want passthrough", rec.Code, called)
	}
}

// TestObserverEnvelopeErrorForNonDomain covers asDomainError's non-domain path
// via a FailClosed gate returning a plain error: the observer emits a typed
// error.internal envelope, never a plain-text 403.
func TestObserverEnvelopeErrorForNonDomain(t *testing.T) {
	gate := preOnly("boom", contracts.FailClosed, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, errBoom
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)

	called := false
	h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (typed envelope)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeInternal) {
		t.Fatalf("body = %q, want the i18n envelope", rec.Body.String())
	}
	if called {
		t.Error("inner handler ran despite a fail-closed gate error")
	}
}

func TestObserverBlocksOnFailClosedGate(t *testing.T) {
	gate := preOnly("closed", contracts.FailClosed, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, errBoom
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)

	called := false
	h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (typed envelope)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), domain.CodeInternal) {
		t.Fatalf("body = %q, want the i18n envelope", rec.Body.String())
	}
	if called {
		t.Error("inner handler ran despite a fail-closed gate error")
	}
}

func TestObserverBlocksOnPreCommitDecision(t *testing.T) {
	for _, kind := range []contracts.DecisionKind{contracts.DecisionBlock, contracts.DecisionReroute} {
		gate := preOnly("decider", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
			d := contracts.Decision{Kind: kind}
			if kind == contracts.DecisionBlock {
				d.Synthetic = &contracts.SyntheticResponse{Status: 200}
			} else {
				d.Reroute = &contracts.RerouteTarget{Provider: "p"}
			}
			return d, nil
		})
		chain, _ := New([]contracts.Gate{gate})
		observer, _ := NewObserver(chain)

		called := false
		h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

		wantStatus := http.StatusNotImplemented
		if kind == contracts.DecisionBlock {
			wantStatus = http.StatusOK // the synthetic's own status
		}
		if rec.Code != wantStatus {
			t.Errorf("kind %v: status = %d, want %d", kind, rec.Code, wantStatus)
		}
		if called {
			t.Errorf("kind %v: inner handler ran despite a pre-commit decision", kind)
		}
	}
}

// TestObserverHeadersAreNamesOnly pins headerNamesOnly: every key survives with a
// nil/empty value, so a gate can see the header is present but cannot read it.
func TestObserverHeadersAreNamesOnly(t *testing.T) {
	var captured http.Header
	gate := captureHeaderGate{onHeaders: func(h http.Header) { captured = h }}
	chain, err := New([]contracts.Gate{gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observer, err := NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}

	handler := observer.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer SUPER-SECRET-TOKEN")
	req.Header.Set("Cookie", "session=SUPER-SECRET-TOKEN")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if len(captured) == 0 {
		t.Fatal("no headers reached the gate")
	}
	for name, vals := range captured {
		for _, v := range vals {
			if v != "" {
				t.Fatalf("header %s carried a value: %q", name, v)
			}
		}
	}
	if _, ok := captured["Authorization"]; !ok {
		t.Error("Authorization name missing")
	}
	if _, ok := captured["Cookie"]; !ok {
		t.Error("Cookie name missing")
	}
}

// captureHeaderGate records the PreRequest Headers.
type captureHeaderGate struct {
	onHeaders func(http.Header)
}

func (captureHeaderGate) ID() string { return "hdr" }
func (captureHeaderGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}
func (captureHeaderGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (captureHeaderGate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }
func (g captureHeaderGate) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if g.onHeaders != nil {
		g.onHeaders(in.Headers)
	}
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (captureHeaderGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (captureHeaderGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (captureHeaderGate) Close() error                                            { return nil }

// TestObserverSkipExcludesGatewayLikeRoutes proves the Skip predicate: a
// skipped request never touches the chain (a stateful gate must not observe
// it twice), while other requests still do.
func TestObserverSkipExcludesGatewayLikeRoutes(t *testing.T) {
	chain, err := New([]contracts.Gate{countingGate{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs, err := NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}
	obs.Skip = func(r *http.Request) bool {
		return r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions"
	}

	var ran int
	handler := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran++
	}))

	// Skipped: the chain never sees it, the handler does.
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if ran != 1 {
		t.Fatal("the wrapped handler must still run for a skipped request")
	}

	// Not skipped: the chain runs (the counting gate observes) on the inference
	// surface.
	other := httptest.NewRequest(http.MethodPost, "/v1/other", nil)
	handler.ServeHTTP(httptest.NewRecorder(), other)
	handler.ServeHTTP(httptest.NewRecorder(), other)
}

// countingGate is a minimal metadata-only gate for observer tests.
type countingGate struct{}

func (g countingGate) ID() string { return "counting" }
func (g countingGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}
func (g countingGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (g countingGate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }
func (g countingGate) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	return contracts.Decision{Kind: contracts.DecisionContinue}, nil
}
func (g countingGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (g countingGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (g countingGate) Close() error                                            { return nil }

// blockingGate always Blocks on the inference surface with a 429 synthetic, so
// the observer's scope test can prove inference is gated while other routes are
// not.
type blockingGate struct{}

func (blockingGate) ID() string { return "blocking" }
func (blockingGate) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}
func (blockingGate) RequiredCaps() contracts.GateCaps       { return 0 }
func (blockingGate) FailurePolicy() contracts.FailurePolicy { return contracts.FailOpen }
func (blockingGate) PreRequest(context.Context, contracts.GateInput) (contracts.Decision, error) {
	d := contracts.Decision{Kind: contracts.DecisionBlock, Code: domain.CodeSecurityRateLimited}
	d.Synthetic = &contracts.SyntheticResponse{Status: http.StatusTooManyRequests}
	return d, nil
}
func (blockingGate) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}
func (blockingGate) PostResponse(context.Context, contracts.GateInput) error { return nil }
func (blockingGate) Close() error                                            { return nil }

// TestObserverSyntheticZeroStatusDefaultsTo200 covers writeEnvelopeError's
// status==0 fallback via a synthetic with an explicit zero status.
func TestObserverSyntheticZeroStatusDefaultsTo200(t *testing.T) {
	gate := preOnly("cache", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		d := contracts.Decision{Kind: contracts.DecisionBlock}
		d.Synthetic = &contracts.SyntheticResponse{Status: 0, Body: []byte(`{}`)}
		return d, nil
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a zero-status synthetic", rec.Code)
	}
}

// TestObserverEnvelopeErrorZeroStatus covers writeEnvelopeError's status==0
// fallback: a FailClosed gate returning a DomainError with no HTTP status still
// emits 500, never a zero status line.
func TestObserverEnvelopeErrorZeroStatus(t *testing.T) {
	gate := preOnly("zerostat", contracts.FailClosed, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, &domain.DomainError{Code: "test.zero_status", HTTPStatus: 0}
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)
	rec := httptest.NewRecorder()
	observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test.zero_status") {
		t.Fatalf("body = %q, want the zero-status code", rec.Body.String())
	}
}
