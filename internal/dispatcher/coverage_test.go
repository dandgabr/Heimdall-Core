package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// cancelExecutor cancels its context then returns a provider error, so the
// dispatcher's post-error ctx check (ADR-0010 §2.3) is reached.
type cancelExecutor struct {
	cancel context.CancelFunc
	err    *domain.DomainError
}

func (e cancelExecutor) Family() domain.ProviderID { return "p1" }
func (e cancelExecutor) Do(context.Context, contracts.WireRequest, contracts.Credential) (contracts.WireResponse, error) {
	e.cancel()
	return contracts.WireResponse{}, e.err
}
func (e cancelExecutor) DoStream(context.Context, contracts.WireRequest, contracts.Credential) (contracts.Stream, error) {
	e.cancel()
	return nil, e.err
}
func (e cancelExecutor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

// cancelFactory builds a cancelExecutor.
type cancelFactory struct{ exec contracts.Executor }

func (f cancelFactory) Build(context.Context, contracts.Candidate, contracts.Credential) (contracts.Executor, error) {
	return f.exec, nil
}

// TestMaxRoundsDefaultsToAttemptCount covers the maxRounds<=0 default.
func TestMaxRoundsDefaultsToAttemptCount(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	// MaxRounds 0: default to len(Attempts)=2, so p2 is still tried.
	resp, err := d.Do(context.Background(), wireReq(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		cand("p1", "m", "c1"), cand("p2", "m", "c2"),
	}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Provider != "p2" {
		t.Fatalf("winner = %+v, want p2", resp)
	}
}

// TestPreflightCtxCancelled covers the ctx check before Build.
func TestPreflightCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(ctx, wireReq(), plan(1, cand("p1", "m", "c1")))
	if asDomain(err).Code != domain.CodeUpstreamTimeout {
		t.Fatalf("err = %v, want upstream_timeout", err)
	}
}

// TestPostErrorCtxCancelled covers the post-error ctx check on the Do path.
func TestPostErrorCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exec := cancelExecutor{cancel: cancel, err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}
	d := newTestDispatcher(cancelFactory{exec: exec}, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(ctx, wireReq(), plan(1, cand("p1", "m", "c1")))
	if asDomain(err).Code != domain.CodeUpstreamTimeout {
		t.Fatalf("err = %v, want upstream_timeout", err)
	}
}

// TestPostErrorCtxCancelledStream covers the post-error ctx check on the stream
// path.
func TestPostErrorCtxCancelledStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exec := cancelExecutor{cancel: cancel, err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}
	d := newTestDispatcher(cancelFactory{exec: exec}, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.DoStream(ctx, wireReq(), plan(1, cand("p1", "m", "c1")))
	if asDomain(err).Code != domain.CodeUpstreamTimeout {
		t.Fatalf("err = %v, want upstream_timeout", err)
	}
}

// TestZeroCredentialLoopDeniesThenExhausts covers the loop's deny `continue`
// and the all-denied skipBreaker return.
func TestZeroCredentialLoopDeniesThenExhausts(t *testing.T) {
	creds := &fakeCreds{
		byProvider: map[domain.ProviderID][]domain.CredentialID{"p1": {"c1", "c2"}},
		byID:       map[domain.CredentialID]contracts.Credential{"c1": {ID: "c1"}, "c2": {ID: "c2"}},
	}
	br := newFakeBreaker()
	br.allow["p1|c1"] = false
	br.allow["p1|c2"] = false
	d := newTestDispatcher(&scriptedFactory{}, creds, br, nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchNoAttempts || de.Scope != domain.ScopeProvider {
		t.Fatalf("err = %+v, want no_attempts/provider", de)
	}
}

// TestZeroCredentialSkipsUnloadable covers the Get-error `continue` inside the
// zero-credential loop.
func TestZeroCredentialSkipsUnloadable(t *testing.T) {
	ex := &fakeExecutor{family: "p1", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	creds := &fakeCreds{
		byProvider: map[domain.ProviderID][]domain.CredentialID{"p1": {"ghost", "c1"}},
		byID:       map[domain.CredentialID]contracts.Credential{"c1": {ID: "c1", Provider: "p1"}},
	}
	d := newTestDispatcher(&scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}, creds, newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	resp, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Credential != "c1" {
		t.Fatalf("credential = %q, want c1", resp.Candidate.Credential)
	}
}

// TestRecordAndAccountNilRecorder covers the nil-recorder early returns.
func TestRecordAndAccountNilRecorder(t *testing.T) {
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), newFakeBreaker(), nil, nil, &fakeWaiter{})
	// These must not panic with a nil recorder.
	d.record(context.Background(), cand("p1", "m", "c1"), contracts.OutcomeProviderError, breaker.Outcome{Scope: domain.ScopeProvider, Retryable: true})
	d.account(context.Background(), cand("p1", "m", "c1"), "k", []byte(`{}`))
}

// TestMarshalSeamFailure covers rewriteModel's two marshal-error branches: the
// FIRST marshal (the model string) failing, and the SECOND (the object) failing.
func TestMarshalSeamFailure(t *testing.T) {
	orig := jsonMarshal
	defer func() { jsonMarshal = orig }()

	// First marshal fails.
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
	in := contracts.WireRequest{Body: []byte(`{"model":"m"}`), Model: "m"}
	got := rewriteModel(in, "other")
	if got.Model != "other" {
		t.Fatalf("model = %q, want other (best-effort)", got.Model)
	}
	if string(got.Body) != `{"model":"m"}` {
		t.Fatalf("body = %s, want untouched on marshal failure", got.Body)
	}

	// Second marshal fails: the model string marshals, the object does not.
	calls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("second marshal boom")
		}
		return json.Marshal(v)
	}
	got = rewriteModel(in, "other")
	if got.Model != "other" || string(got.Body) != `{"model":"m"}` {
		t.Fatalf("second-marshal failure = %s / %s, want model set and body untouched", got.Model, got.Body)
	}
}
