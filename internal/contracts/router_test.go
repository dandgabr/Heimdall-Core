package contracts

import (
	"context"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file pins the F3 contract surface: enum String/parse round-trips, the
// terminal rule, the breaker key derivation and the strategy vocabulary. The
// interfaces themselves need no test beyond a compile-time assertion (the fakes
// below), because they carry no executable logic.

var (
	_ Router        = (*fakeRouter)(nil)
	_ Dispatcher    = (*fakeDispatcher)(nil)
	_ QuotaFilter   = (*fakeQuotaFilter)(nil)
	_ UsageRecorder = (*fakeUsageRecorder)(nil)
	_ Breaker       = (*fakeBreaker)(nil)
)

func TestStrategyKindStringAndParse(t *testing.T) {
	all := Strategies()
	if len(all) != 10 {
		t.Fatalf("Strategies() = %d, want 10 (the ADR-0009 set)", len(all))
	}
	for _, k := range all {
		if k.String() != string(k) {
			t.Errorf("%q.String() = %q", k, k.String())
		}
		got, ok := ParseStrategyKind(string(k))
		if !ok || got != k {
			t.Errorf("ParseStrategyKind(%q) = %v, %v", k, got, ok)
		}
	}
	if StrategyKind("nope").String() != "" {
		t.Error("unknown strategy String() did not return empty")
	}
	if _, ok := ParseStrategyKind("nope"); ok {
		t.Error("ParseStrategyKind accepted an unknown strategy")
	}
	if _, ok := ParseStrategyKind(""); ok {
		t.Error("ParseStrategyKind accepted an empty strategy")
	}

	// Strategies returns a copy: mutating it must not affect the package set.
	all[0] = "mutated"
	if Strategies()[0] == "mutated" {
		t.Error("Strategies() returned the internal slice")
	}
}

func TestAttemptOutcomeStringAndTerminal(t *testing.T) {
	tests := []struct {
		outcome  AttemptOutcome
		want     string
		terminal bool
	}{
		{OutcomeSuccess, "success", false},
		{OutcomeClientError, "client_error", true},
		{OutcomeCredentialError, "credential_error", false},
		{OutcomeProviderError, "provider_error", false},
		{OutcomeTransient, "transient", false},
		{AttemptOutcome(99), "unknown", false},
	}
	for _, tt := range tests {
		if got := tt.outcome.String(); got != tt.want {
			t.Errorf("AttemptOutcome(%d).String() = %q, want %q", tt.outcome, got, tt.want)
		}
		if got := tt.outcome.IsTerminal(); got != tt.terminal {
			t.Errorf("AttemptOutcome(%d).IsTerminal() = %v, want %v", tt.outcome, got, tt.terminal)
		}
	}
}

func TestWindowKindAndQuotaSourceString(t *testing.T) {
	kinds := map[WindowKind]string{
		WindowShort: "short", WindowLong: "long", WindowCost: "cost", WindowKind(99): "unknown",
	}
	for k, want := range kinds {
		if got := k.String(); got != want {
			t.Errorf("WindowKind(%d).String() = %q, want %q", k, got, want)
		}
	}
	sources := map[QuotaSource]string{
		SourceLocalCounter: "local_counter", SourceRetryHint: "retry_hint",
		SourceHeader: "header", QuotaSource(99): "unknown",
	}
	for s, want := range sources {
		if got := s.String(); got != want {
			t.Errorf("QuotaSource(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestBreakerScopeStringAndKeyFor(t *testing.T) {
	scopes := map[BreakerScope]string{
		BreakerProvider: "provider", BreakerCredential: "credential",
		BreakerModel: "model", BreakerScope(99): "unknown",
	}
	for s, want := range scopes {
		if got := s.String(); got != want {
			t.Errorf("BreakerScope(%d).String() = %q, want %q", s, got, want)
		}
	}

	c := Candidate{
		Provider:   domain.ProviderID("z.ai"),
		Model:      domain.ModelID("glm-5"),
		Credential: domain.CredentialID("cred-1"),
	}
	// Each scope sets exactly its own fields.
	provider := KeyFor(c, BreakerProvider)
	if provider.Provider != "z.ai" || provider.Credential != "" || provider.Model != "" {
		t.Errorf("provider key = %+v", provider)
	}
	cred := KeyFor(c, BreakerCredential)
	if cred.Provider != "z.ai" || cred.Credential != "cred-1" || cred.Model != "" {
		t.Errorf("credential key = %+v", cred)
	}
	model := KeyFor(c, BreakerModel)
	if model.Provider != "z.ai" || model.Model != "glm-5" || model.Credential != "" {
		t.Errorf("model key = %+v", model)
	}
}

func TestBreakerStateString(t *testing.T) {
	states := map[BreakerState]string{
		BreakerClosed: "closed", BreakerOpen: "open",
		BreakerHalfOpen: "half_open", BreakerTerminal: "terminal",
		BreakerState(99): "unknown",
	}
	for s, want := range states {
		if got := s.String(); got != want {
			t.Errorf("BreakerState(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// --- fakes (compile-time interface satisfaction) ---

type fakeRouter struct{}

func (fakeRouter) Resolve(ctx context.Context, _ *Request, _ domain.ComboID) (RoutePlan, error) {
	return RoutePlan{}, nil
}

type fakeDispatcher struct{}

func (fakeDispatcher) Do(ctx context.Context, _ WireRequest, _ RoutePlan) (*Response, error) {
	return nil, nil
}
func (fakeDispatcher) DoStream(ctx context.Context, _ WireRequest, _ RoutePlan) (Stream, error) {
	return nil, nil
}

type fakeQuotaFilter struct{}

func (fakeQuotaFilter) Filter(ctx context.Context, plan RoutePlan) (RoutePlan, []Skip) {
	return plan, nil
}

type fakeUsageRecorder struct{}

func (fakeUsageRecorder) Record(ctx context.Context, _ AttemptOutcome, _ Usage) error { return nil }
func (fakeUsageRecorder) Snapshot(ctx context.Context, _ domain.CredentialID) (QuotaState, bool) {
	return QuotaState{}, false
}

type fakeBreaker struct{}

func (fakeBreaker) Allow(Candidate) bool                      { return true }
func (fakeBreaker) OnResult(Candidate, AttemptOutcome, Usage) {}
func (fakeBreaker) RetryAfter(Candidate) time.Duration        { return 0 }
