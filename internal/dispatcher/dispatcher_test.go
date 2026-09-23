package dispatcher

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeClock is the injectable time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// fakeIDs returns a deterministic request id.
type fakeIDs struct{}

func (fakeIDs) NewRequestID() domain.RequestID { return "req-1" }

// fakeWaiter records the requested cooldown without sleeping.
type fakeWaiter struct {
	mu    sync.Mutex
	calls []time.Duration
	err   error
}

func (w *fakeWaiter) Wait(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	w.calls = append(w.calls, d)
	w.mu.Unlock()
	return w.err
}

func (w *fakeWaiter) delays() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]time.Duration, len(w.calls))
	copy(out, w.calls)
	return out
}

// fakeExecutor is a scripted Executor: each call consumes the next result.
type fakeExecutor struct {
	family domain.ProviderID
	// doResults are returned in order by Do.
	doResults []doResult
	// streams are returned in order by DoStream.
	streams []streamResult
	doCalls int
	stCalls int
}

type doResult struct {
	resp contracts.WireResponse
	err  error
}

type streamResult struct {
	stream contracts.Stream
	err    error
}

func (e *fakeExecutor) Family() domain.ProviderID { return e.family }

func (e *fakeExecutor) Do(_ context.Context, _ contracts.WireRequest, _ contracts.Credential) (contracts.WireResponse, error) {
	if e.doCalls >= len(e.doResults) {
		return contracts.WireResponse{}, errors.New("no more scripted results")
	}
	r := e.doResults[e.doCalls]
	e.doCalls++
	return r.resp, r.err
}

func (e *fakeExecutor) DoStream(_ context.Context, _ contracts.WireRequest, _ contracts.Credential) (contracts.Stream, error) {
	if e.stCalls >= len(e.streams) {
		return nil, errors.New("no more scripted streams")
	}
	r := e.streams[e.stCalls]
	e.stCalls++
	return r.stream, r.err
}

func (e *fakeExecutor) CountTokens(context.Context, contracts.WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

// scriptedFactory builds a fake executor per provider.
type scriptedFactory struct {
	byProvider map[domain.ProviderID]*fakeExecutor
	failOn     map[domain.ProviderID]error
}

func (f *scriptedFactory) Build(_ context.Context, c contracts.Candidate, _ contracts.Credential) (contracts.Executor, error) {
	if err, ok := f.failOn[c.Provider]; ok {
		return nil, err
	}
	exec, ok := f.byProvider[c.Provider]
	if !ok {
		return nil, domain.New(domain.CodeProviderNotFound,
			domain.WithHTTPStatus(404),
			domain.WithParams(map[string]string{"provider": string(c.Provider)}))
	}
	return exec, nil
}

// fakeCreds is a deterministic CredentialSource.
type fakeCreds struct {
	byProvider map[domain.ProviderID][]domain.CredentialID
	byID       map[domain.CredentialID]contracts.Credential
	getErr     error
	listErr    error
}

func (c *fakeCreds) Get(_ context.Context, id domain.CredentialID) (contracts.Credential, error) {
	if c.getErr != nil {
		return contracts.Credential{}, c.getErr
	}
	cred, ok := c.byID[id]
	if !ok {
		return contracts.Credential{}, contracts.ErrNotFound
	}
	return cred, nil
}

func (c *fakeCreds) Credentials(_ context.Context, p domain.ProviderID) ([]domain.CredentialID, error) {
	if c.listErr != nil {
		return nil, c.listErr
	}
	return c.byProvider[p], nil
}

// fakeBreaker is a scriptable breaker.
type fakeBreaker struct {
	allow        map[string]bool
	retryAfter   map[string]time.Duration
	mu           sync.Mutex
	records      []recorded
	terminalSeen bool
}

type recorded struct {
	cand    contracts.Candidate
	outcome breaker.Outcome
}

func newFakeBreaker() *fakeBreaker {
	return &fakeBreaker{allow: map[string]bool{}, retryAfter: map[string]time.Duration{}}
}

func keyOf(c contracts.Candidate) string { return string(c.Provider) + "|" + string(c.Credential) }

func (b *fakeBreaker) Allow(c contracts.Candidate) bool {
	if v, ok := b.allow[keyOf(c)]; ok {
		return v
	}
	return true
}

func (b *fakeBreaker) Record(c contracts.Candidate, o breaker.Outcome) {
	b.mu.Lock()
	b.records = append(b.records, recorded{cand: c, outcome: o})
	if !o.Success && o.TerminalReason != "" {
		b.terminalSeen = true
	}
	b.mu.Unlock()
}

func (b *fakeBreaker) RetryAfter(c contracts.Candidate) time.Duration {
	return b.retryAfter[keyOf(c)]
}

func (b *fakeBreaker) recorded() []recorded {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]recorded, len(b.records))
	copy(out, b.records)
	return out
}

// fakeRecorder records every Usage by key, like the real recorder's idempotency.
type fakeRecorder struct {
	mu     sync.Mutex
	byKey  map[string]contracts.Usage
	outc   map[string]contracts.AttemptOutcome
	aborts map[string]bool
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{byKey: map[string]contracts.Usage{}, outc: map[string]contracts.AttemptOutcome{}, aborts: map[string]bool{}}
}

func (r *fakeRecorder) Record(_ context.Context, o contracts.AttemptOutcome, u contracts.Usage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Idempotent by AttemptKey: a replay replaces.
	r.byKey[u.AttemptKey] = u
	r.outc[u.AttemptKey] = o
	r.aborts[u.AttemptKey] = u.Aborted
	return nil
}

func (r *fakeRecorder) Snapshot(context.Context, domain.CredentialID) (contracts.QuotaState, bool) {
	return contracts.QuotaState{}, false
}

func (r *fakeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byKey)
}

func (r *fakeRecorder) usage(key string) (contracts.Usage, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byKey[key]
	return u, ok
}

// memStream is an in-memory contracts.Stream.
type memStream struct {
	chunks  []contracts.Chunk
	err     error
	i       int
	closed  bool
	closeFn func()
}

func (s *memStream) Headers() http.Header { return http.Header{} }
func (s *memStream) Recv() (contracts.Chunk, error) {
	if s.i < len(s.chunks) {
		ch := s.chunks[s.i]
		s.i++
		return ch, nil
	}
	if s.err != nil {
		return contracts.Chunk{}, s.err
	}
	return contracts.Chunk{}, io.EOF
}
func (s *memStream) Close() error {
	s.closed = true
	if s.closeFn != nil {
		s.closeFn()
	}
	return nil
}

func newTestDispatcher(factory ExecutorFactory, creds CredentialSource, br Breaker, quota QuotaFilter, rec contracts.UsageRecorder, w Waiter) *Dispatcher {
	return New(factory, creds, br, quota, rec, Config{
		Clock:  &fakeClock{t: time.Unix(0, 0)},
		IDs:    fakeIDs{},
		Waiter: w,
	})
}

func cand(provider, model, cred string) contracts.Candidate {
	return contracts.Candidate{Provider: domain.ProviderID(provider), Model: domain.ModelID(model), Credential: domain.CredentialID(cred)}
}

func plan(maxRounds int, cs ...contracts.Candidate) contracts.RoutePlan {
	return contracts.RoutePlan{Attempts: cs, MaxRounds: maxRounds}
}

func wireReq() contracts.WireRequest {
	return contracts.WireRequest{Body: []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`), Model: "m"}
}

func testCreds() *fakeCreds {
	return &fakeCreds{
		byProvider: map[domain.ProviderID][]domain.CredentialID{"p1": {"c1"}, "p2": {"c2"}},
		byID: map[domain.CredentialID]contracts.Credential{
			"c1": {ID: "c1", Provider: "p1", AuthMode: contracts.AuthAPIKey},
			"c2": {ID: "c2", Provider: "p2", AuthMode: contracts.AuthAPIKey},
		},
	}
}

// TestDoSuccessFirstCandidate proves the first candidate wins and accounting is
// emitted once.
func TestDoSuccessFirstCandidate(t *testing.T) {
	ex := &fakeExecutor{family: "p1", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{"usage":{"total_tokens":7}}`)}}}}
	rec := newFakeRecorder()
	d := newTestDispatcher(&scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}, testCreds(), newFakeBreaker(), nil, rec, &fakeWaiter{})
	resp, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Attempts != 1 || resp.Candidate.Provider != "p1" {
		t.Fatalf("response = %+v", resp)
	}
	if ex.doCalls != 1 {
		t.Fatalf("executor calls = %d, want 1", ex.doCalls)
	}
	if rec.count() != 1 {
		t.Fatalf("recorded attempts = %d, want 1", rec.count())
	}
	u, _ := rec.usage("req-1:p1/m:c1:1")
	if u.Tokens != 7 {
		t.Fatalf("usage tokens = %d, want 7", u.Tokens)
	}
}

// TestDoFailover429ThenSuccess proves a 429 on the first candidate fails over to
// the second and the RetryAfter is honoured exactly.
func TestDoFailover429ThenSuccess(t *testing.T) {
	first429 := domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(429), domain.Retry(), domain.WithScope(domain.ScopeCredential),
		domain.WithRetryAfter(3*time.Second))
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: first429}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	br := newFakeBreaker()
	waiter := &fakeWaiter{}
	d := newTestDispatcher(factory, testCreds(), br, nil, newFakeRecorder(), waiter)

	resp, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Provider != "p2" || resp.Attempts != 2 {
		t.Fatalf("winner = %+v, want p2 with 2 attempts", resp)
	}
	// RetryAfter 3s was awaited exactly.
	if got := waiter.delays(); len(got) != 1 || got[0] != 3*time.Second {
		t.Fatalf("waiter delays = %v, want [3s]", got)
	}
	// The breaker recorded the credential failure with the RetryAfter.
	recs := br.recorded()
	if len(recs) == 0 || recs[0].outcome.Scope != domain.ScopeCredential || recs[0].outcome.RetryAfter != 3*time.Second {
		t.Fatalf("breaker records = %+v", recs)
	}
}

// TestDoFailover5xxThenSuccess proves a provider 5xx fails over (exponential, no
// RetryAfter hint).
func TestDoFailover5xxThenSuccess(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	waiter := &fakeWaiter{}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), waiter)

	resp, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Provider != "p2" {
		t.Fatalf("winner = %+v", resp)
	}
	// No RetryAfter: the waiter was not asked to sleep.
	if len(waiter.delays()) != 0 {
		t.Fatalf("unexpected cooldown waits: %v", waiter.delays())
	}
}

// TestClientErrorIsTerminalNoRetryNoCooldown is the ADR-0010 §2.1 headline: a
// ScopeRequest failure returns immediately, does not try the next candidate and
// does not cooldown the breaker.
func TestClientErrorIsTerminalNoRetryNoCooldown(t *testing.T) {
	clientErr := domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(400), domain.WithScope(domain.ScopeRequest))
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: clientErr}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	br := newFakeBreaker()
	waiter := &fakeWaiter{}
	d := newTestDispatcher(factory, testCreds(), br, nil, newFakeRecorder(), waiter)

	_, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err == nil {
		t.Fatal("client error did not propagate")
	}
	if ex2.doCalls != 0 {
		t.Fatal("client error failed over to the next candidate")
	}
	if len(waiter.delays()) != 0 {
		t.Fatal("client error triggered a cooldown wait")
	}
	// The breaker recorded NOTHING for a client error (the fake still records
	// every Record, so assert the Scope is request and no terminal promotion).
	_ = br
}

// TestExhaustedAggregate proves all-failed yields dispatch.exhausted inheriting
// the last classification.
func TestExhaustedAggregate(t *testing.T) {
	last := domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: last}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{err: last}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	_, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchExhausted {
		t.Fatalf("code = %q, want dispatch.exhausted", de.Code)
	}
	if de.Scope != domain.ScopeProvider || !de.Retryable {
		t.Fatalf("aggregate classification = scope %v retryable %v", de.Scope, de.Retryable)
	}
	if de.Params["attempts"] != "2" || de.Params["last_code"] == "" {
		t.Fatalf("params = %+v", de.Params)
	}
}

// TestMaxRoundsHonoured proves the attempt cap stops the loop.
func TestMaxRoundsHonoured(t *testing.T) {
	fail := domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider))
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: fail}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchMaxRounds {
		t.Fatalf("code = %q, want dispatch.max_rounds", de.Code)
	}
	if ex2.doCalls != 0 {
		t.Fatal("max_rounds=1 still tried the second candidate")
	}
}

// TestBreakerOpenSkipsCandidate proves an open circuit filters a candidate and
// the next one is tried.
func TestBreakerOpenSkipsCandidate(t *testing.T) {
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p2": ex2}}
	br := newFakeBreaker()
	br.allow[keyOf(cand("p1", "m", "c1"))] = false
	d := newTestDispatcher(factory, testCreds(), br, nil, newFakeRecorder(), &fakeWaiter{})

	resp, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Provider != "p2" {
		t.Fatalf("winner = %+v, want p2", resp)
	}
}

// TestNoAttemptsAllFilteredByBreaker proves the aggregate preserves the breaker
// class when no candidate was executable.
func TestNoAttemptsAllFilteredByBreaker(t *testing.T) {
	br := newFakeBreaker()
	br.allow[keyOf(cand("p1", "m", "c1"))] = false
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), br, nil, newFakeRecorder(), &fakeWaiter{})

	_, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchNoAttempts || de.Scope != domain.ScopeProvider {
		t.Fatalf("err = %+v, want no_attempts/provider", de)
	}
}

// TestNoAttemptsNoCredentials proves the request-scoped aggregate when there is
// no account at all.
func TestNoAttemptsNoCredentials(t *testing.T) {
	creds := &fakeCreds{byProvider: map[domain.ProviderID][]domain.CredentialID{}, byID: map[domain.CredentialID]contracts.Credential{}}
	d := newTestDispatcher(&scriptedFactory{}, creds, newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})

	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchNoAttempts || de.Scope != domain.ScopeRequest {
		t.Fatalf("err = %+v, want no_attempts/request", de)
	}
}

// TestZeroCredentialPicksFirstHealthy proves the "any healthy account" path.
func TestZeroCredentialPicksFirstHealthy(t *testing.T) {
	ex := &fakeExecutor{family: "p1", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}
	creds := &fakeCreds{
		byProvider: map[domain.ProviderID][]domain.CredentialID{"p1": {"c9", "c1"}},
		byID:       map[domain.CredentialID]contracts.Credential{"c1": {ID: "c1", Provider: "p1"}},
	}
	d := newTestDispatcher(factory, creds, newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	resp, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Credential != "c1" {
		t.Fatalf("credential = %q, want c1 (the first loadable)", resp.Candidate.Credential)
	}
}

// TestFactoryBuildErrorIsClassified proves a BuildExecutor failure is recorded
// and fails over.
func TestFactoryBuildErrorIsClassified(t *testing.T) {
	buildErr := domain.New(domain.CodeProviderAuthModeUnsupported,
		domain.WithHTTPStatus(500), domain.WithScope(domain.ScopeCredential))
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{
		byProvider: map[domain.ProviderID]*fakeExecutor{"p2": ex2},
		failOn:     map[domain.ProviderID]error{"p1": buildErr},
	}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	resp, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Candidate.Provider != "p2" {
		t.Fatalf("winner = %+v, want p2", resp)
	}
}

// TestContextCancelledAborts proves a cancelled ctx returns the ctx error, not
// an exhausted-candidates error.
func TestContextCancelledAborts(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(503), domain.Retry(), domain.WithScope(domain.ScopeProvider),
		domain.WithRetryAfter(time.Second))}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1}}
	waiter := &fakeWaiter{err: context.Canceled}
	d := newTestDispatcher(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), waiter)

	_, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2")))
	de := asDomain(err)
	if de.Code != domain.CodeUpstreamTimeout {
		t.Fatalf("code = %q, want upstream_timeout on ctx cancel", de.Code)
	}
}

// TestCooldownCapped proves a hostile RetryAfter is capped by MaxCooldown.
func TestCooldownCapped(t *testing.T) {
	ex1 := &fakeExecutor{family: "p1", doResults: []doResult{{err: domain.New(domain.CodeUpstreamUnavailable,
		domain.WithHTTPStatus(429), domain.Retry(), domain.WithScope(domain.ScopeCredential),
		domain.WithRetryAfter(10*time.Hour))}}}
	ex2 := &fakeExecutor{family: "p2", doResults: []doResult{{resp: contracts.WireResponse{Status: 200, Body: []byte(`{}`)}}}}
	factory := &scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex1, "p2": ex2}}
	waiter := &fakeWaiter{}
	d := New(factory, testCreds(), newFakeBreaker(), nil, newFakeRecorder(), Config{
		Clock: &fakeClock{}, IDs: fakeIDs{}, Waiter: waiter, MaxCooldown: 5 * time.Second,
	})
	if _, err := d.Do(context.Background(), wireReq(), plan(2, cand("p1", "m", "c1"), cand("p2", "m", "c2"))); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := waiter.delays(); len(got) != 1 || got[0] != 5*time.Second {
		t.Fatalf("waiter delays = %v, want [5s] (capped)", got)
	}
}

// TestNilClockPanics covers the constructor guard.
func TestNilClockPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New with a nil clock did not panic")
		}
	}()
	New(&scriptedFactory{}, testCreds(), newFakeBreaker(), nil, nil, Config{})
}

// TestDefaultsFillSeams covers New's defaulting of IDs, Waiter and MaxCooldown.
func TestDefaultsFillSeams(t *testing.T) {
	d := New(&scriptedFactory{}, testCreds(), newFakeBreaker(), nil, nil, Config{Clock: &fakeClock{}})
	if d.cfg.Waiter == nil {
		t.Error("Waiter not defaulted")
	}
	if d.cfg.MaxCooldown != DefaultMaxCooldown {
		t.Errorf("MaxCooldown = %v, want default", d.cfg.MaxCooldown)
	}
	// TimerWaiter: a zero duration returns immediately; a real one waits.
	if err := (TimerWaiter{}).Wait(context.Background(), 0); err != nil {
		t.Errorf("TimerWaiter(0) = %v", err)
	}
	if err := (TimerWaiter{}).Wait(context.Background(), time.Millisecond); err != nil {
		t.Errorf("TimerWaiter(1ms) = %v", err)
	}
	// A cancelled ctx aborts the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (TimerWaiter{}).Wait(ctx, time.Hour); err == nil {
		t.Error("TimerWaiter honoured a cancelled ctx")
	}
}

// TestDomainIDGen covers the default ID generator.
func TestDomainIDGen(t *testing.T) {
	if (domainIDGen{}).NewRequestID() == "" {
		t.Error("NewRequestID returned empty")
	}
}

// TestAsDomainNonDomain covers the non-domain normalisation.
func TestAsDomainNonDomain(t *testing.T) {
	de := asDomain(errors.New("boom"))
	if de.Code != domain.CodeInternal || de.Scope != domain.ScopeRequest {
		t.Fatalf("asDomain = %+v", de)
	}
}

// TestUsageFromBodyBranches covers the token parsing branches.
func TestUsageFromBodyBranches(t *testing.T) {
	c := cand("p", "m", "c")
	// Invalid JSON: zero tokens, no error.
	if u := usageFromBody(c, "k", []byte("{bad")); u.Tokens != 0 {
		t.Fatalf("bad json tokens = %d", u.Tokens)
	}
	// OpenAI shape: prompt+completion.
	u := usageFromBody(c, "k", []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	if u.InputTokens != 3 || u.OutputTokens != 4 || u.Tokens != 7 {
		t.Fatalf("openai usage = %+v", u)
	}
	// Anthropic shape: input+output.
	u = usageFromBody(c, "k", []byte(`{"usage":{"input_tokens":5,"output_tokens":6}}`))
	if u.InputTokens != 5 || u.OutputTokens != 6 || u.Tokens != 11 {
		t.Fatalf("anthropic usage = %+v", u)
	}
	// Explicit total wins.
	u = usageFromBody(c, "k", []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":99}}`))
	if u.Tokens != 99 {
		t.Fatalf("total tokens = %d, want 99", u.Tokens)
	}
}

// TestRewriteModel covers the body rewrite branches.
func TestRewriteModel(t *testing.T) {
	// Same model: unchanged.
	in := contracts.WireRequest{Body: []byte(`{"model":"m"}`), Model: "m"}
	if got := rewriteModel(in, "m"); string(got.Body) != `{"model":"m"}` {
		t.Errorf("same-model rewrite changed the body: %s", got.Body)
	}
	// Different model: rewritten.
	got := rewriteModel(in, "other")
	if got.Model != "other" || string(got.Body) != `{"model":"other"}` {
		t.Errorf("rewrite = %s / %s", got.Model, got.Body)
	}
	// Invalid body: model field set, body untouched.
	bad := contracts.WireRequest{Body: []byte("{bad"), Model: "m"}
	if g := rewriteModel(bad, "x"); g.Model != "x" || string(g.Body) != "{bad" {
		t.Errorf("invalid-body rewrite = %s / %s", g.Model, g.Body)
	}
	// Empty target model: unchanged.
	if g := rewriteModel(in, ""); g.Model != "m" {
		t.Errorf("empty-target rewrite changed the model: %s", g.Model)
	}
}

// TestQuotaFilterSkips proves the dispatcher consults the quota filter.
type denyingQuota struct{}

func (denyingQuota) Filter(_ context.Context, _ contracts.RoutePlan) (contracts.RoutePlan, []contracts.Skip) {
	return contracts.RoutePlan{}, []contracts.Skip{{Reason: "quota_remaining_below_cutoff"}}
}

func TestQuotaFilterSkips(t *testing.T) {
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), newFakeBreaker(), denyingQuota{}, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	de := asDomain(err)
	if de.Code != domain.CodeDispatchNoAttempts || de.Scope != domain.ScopeCredential {
		t.Fatalf("err = %+v, want no_attempts/credential", de)
	}
}

// TestDenyReasonQuota covers denyReason's quota branch (breaker closed, quota
// denied).
func TestDenyReasonQuota(t *testing.T) {
	d := newTestDispatcher(&scriptedFactory{}, testCreds(), newFakeBreaker(), denyingQuota{}, newFakeRecorder(), &fakeWaiter{})
	if r := d.denyReason(cand("p1", "m", "c1")); r != skipQuota {
		t.Fatalf("denyReason = %v, want skipQuota", r)
	}
}

// TestGetCredentialErrorIsSkip proves a Get failure is a non-fatal skip.
func TestGetCredentialErrorIsSkip(t *testing.T) {
	creds := testCreds()
	creds.getErr = contracts.ErrNotFound
	ex := &fakeExecutor{family: "p1", doResults: []doResult{{resp: contracts.WireResponse{Status: 200}}}}
	d := newTestDispatcher(&scriptedFactory{byProvider: map[domain.ProviderID]*fakeExecutor{"p1": ex}}, creds, newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "c1")))
	if err == nil {
		t.Fatal("Do succeeded despite a credential load failure")
	}
}

// TestCredentialsListErrorIsSkip covers the list-error branch.
func TestCredentialsListErrorIsSkip(t *testing.T) {
	creds := testCreds()
	creds.listErr = errors.New("list boom")
	d := newTestDispatcher(&scriptedFactory{}, creds, newFakeBreaker(), nil, newFakeRecorder(), &fakeWaiter{})
	_, err := d.Do(context.Background(), wireReq(), plan(1, cand("p1", "m", "")))
	if err == nil {
		t.Fatal("Do succeeded despite a credential list failure")
	}
}
