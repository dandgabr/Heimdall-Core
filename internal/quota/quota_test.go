package quota

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fixedClock is the injectable time source; advancing it moves window resets
// without sleeping.
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *fixedClock {
	return &fixedClock{t: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
}

// fakePersistence is an in-memory Persistence that counts writes and can inject
// errors, so the durable branches are exercised without SQLite.
type fakePersistence struct {
	mu       sync.Mutex
	windows  map[domain.CredentialID][]contracts.QuotaWindow
	attempts map[string]contracts.Usage
	outcomes map[string]string
	snapErr  error
	upsErr   error
	recErr   error
	gets     int
}

func newFakePersistence() *fakePersistence {
	return &fakePersistence{
		windows:  make(map[domain.CredentialID][]contracts.QuotaWindow),
		attempts: make(map[string]contracts.Usage),
		outcomes: make(map[string]string),
	}
}

func (f *fakePersistence) Snapshot(_ context.Context, cred domain.CredentialID) (contracts.QuotaState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapErr != nil {
		return contracts.QuotaState{}, false, f.snapErr
	}
	w, ok := f.windows[cred]
	if !ok {
		return contracts.QuotaState{}, false, nil
	}
	return contracts.QuotaState{Credential: cred, Windows: w}, true, nil
}

func (f *fakePersistence) UpsertWindow(_ context.Context, cred domain.CredentialID, w contracts.QuotaWindow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsErr != nil {
		return f.upsErr
	}
	ws := f.windows[cred]
	replaced := false
	for i := range ws {
		if ws[i].Kind == w.Kind {
			ws[i] = w
			replaced = true
		}
	}
	if !replaced {
		ws = append(ws, w)
	}
	f.windows[cred] = ws
	return nil
}

func (f *fakePersistence) GetAttempt(_ context.Context, key string) (contracts.Usage, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	u, ok := f.attempts[key]
	return u, ok, nil
}

func (f *fakePersistence) RecordAttempt(_ context.Context, u contracts.Usage, outcome string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recErr != nil {
		return false, f.recErr
	}
	_, replaced := f.attempts[u.AttemptKey]
	f.attempts[u.AttemptKey] = u
	f.outcomes[u.AttemptKey] = outcome
	return replaced, nil
}

func (f *fakePersistence) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.attempts)
}

// win returns a pointer to the window of a kind in a returned QuotaState, or
// nil. Snapshot returns the frozen contracts.QuotaState (a value), which has no
// unexported accessor, so the test carries its own lookup.
func win(st contracts.QuotaState, kind contracts.WindowKind) *contracts.QuotaWindow {
	for i := range st.Windows {
		if st.Windows[i].Kind == kind {
			return &st.Windows[i]
		}
	}
	return nil
}

func usageInput(cred domain.CredentialID, key string, tokens int) contracts.Usage {
	return contracts.Usage{
		AttemptKey: key,
		Provider:   "zai",
		Credential: cred,
		Model:      "glm",
		Tokens:     tokens,
		Requests:   1,
		CostMicros: 5,
	}
}

// tokenCfg builds a config with a known token ceiling on the short window so the
// percentage decision is exercised.
func tokenCfg(clock contracts.Clock) Config {
	return Config{
		Cutoff: 0.05,
		Windows: []WindowSpec{
			{Kind: contracts.WindowShort, Unit: UnitTokens, Limit: 100, Duration: shortWindow},
		},
		Clock: clock,
	}
}

func TestNewFilterRejectsNilClock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewFilter(nil clock) did not panic")
		}
	}()
	NewFilter(nil, Config{})
}

func TestNewRecorderRejectsNilClock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewRecorder(nil clock) did not panic")
		}
	}()
	NewRecorder(nil, Config{})
}

func TestUnitValue(t *testing.T) {
	u := contracts.Usage{Tokens: 10, Requests: 2, CostMicros: 7}
	if got := UnitTokens.value(u); got != 10 {
		t.Errorf("tokens = %v", got)
	}
	if got := UnitRequests.value(u); got != 2 {
		t.Errorf("requests = %v", got)
	}
	if got := UnitCost.value(u); got != 7 {
		t.Errorf("cost = %v", got)
	}
	if got := Unit(99).value(u); got != 0 {
		t.Errorf("unknown unit = %v, want 0", got)
	}
}

func TestDefaultWindowsAndConfig(t *testing.T) {
	ws := DefaultWindows()
	if len(ws) != 3 {
		t.Fatalf("DefaultWindows = %d, want 3", len(ws))
	}
	if ws[0].Kind != contracts.WindowShort || ws[1].Kind != contracts.WindowLong || ws[2].Kind != contracts.WindowCost {
		t.Fatalf("window kinds = %+v", ws)
	}
	cfg := DefaultConfig(newClock())
	if cfg.Cutoff != DefaultCutoff {
		t.Errorf("cutoff = %v", cfg.Cutoff)
	}
	if len(cfg.Windows) != 3 {
		t.Errorf("config windows = %d", len(cfg.Windows))
	}
	if cfg.Clock == nil {
		t.Error("clock not set")
	}
}

func TestConfigNormaliseClampsCutoff(t *testing.T) {
	neg := Config{Cutoff: -1, Clock: newClock()}.normalise()
	if neg.Cutoff != 0 {
		t.Errorf("negative cutoff = %v, want 0", neg.Cutoff)
	}
	big := Config{Cutoff: 2, Clock: newClock()}.normalise()
	if big.Cutoff != 1 {
		t.Errorf("cutoff > 1 = %v, want 1", big.Cutoff)
	}
	empty := Config{Clock: newClock()}.normalise()
	if len(empty.Windows) != 3 {
		t.Errorf("empty windows not defaulted: %d", len(empty.Windows))
	}
}

func TestCutoffForPerWindow(t *testing.T) {
	cfg := Config{
		Cutoff:  0.1,
		Cutoffs: map[contracts.WindowKind]float64{contracts.WindowShort: 0.25},
		Clock:   newClock(),
	}
	if got := cfg.cutoffFor(contracts.WindowShort); got != 0.25 {
		t.Errorf("short cutoff = %v, want 0.25", got)
	}
	if got := cfg.cutoffFor(contracts.WindowLong); got != 0.1 {
		t.Errorf("long cutoff = %v, want fallback 0.1", got)
	}
}

func TestSpecForKnownAndUnknown(t *testing.T) {
	cfg := DefaultConfig(newClock()).normalise()
	if _, ok := cfg.specFor(contracts.WindowShort); !ok {
		t.Error("short spec not found")
	}
	spec, ok := cfg.specFor(contracts.WindowKind(99))
	if ok {
		t.Error("unknown spec reported found")
	}
	if spec.Duration == 0 {
		t.Error("unknown spec has no default duration")
	}
}

// TestFilterNoReaderIsPassthrough covers the nil-reader no-op.
func TestFilterNoReaderIsPassthrough(t *testing.T) {
	f := NewFilter(nil, Config{Clock: newClock()})
	plan := contracts.RoutePlan{Attempts: []contracts.Candidate{{Provider: "p", Model: "m"}}}
	got, skips := f.Filter(context.Background(), plan)
	if len(got.Attempts) != 1 || len(skips) != 0 {
		t.Fatalf("passthrough changed the plan: %+v %+v", got, skips)
	}
}

// TestFilterBlocksBelowCutoff proves the percentage rule: used 95/100 leaves
// 5% which is <= the 5% cutoff, so the candidate is skipped.
func TestFilterBlocksBelowCutoff(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, tokenCfg(clock))
	cred := domain.CredentialID("acct-1")
	if err := rec.Record(context.Background(), contracts.OutcomeSuccess,
		usageInput(cred, "r:1", 95)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	f := NewFilter(rec, tokenCfg(clock))
	plan := contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm", Credential: cred},
		{Provider: "zai", Model: "glm", Credential: "acct-2"}, // no state -> kept
	}}
	got, skips := f.Filter(context.Background(), plan)
	if len(got.Attempts) != 1 || got.Attempts[0].Credential != "acct-2" {
		t.Fatalf("filtered plan = %+v", got.Attempts)
	}
	if len(skips) != 1 {
		t.Fatalf("skips = %+v", skips)
	}
	if skips[0].Reason != "quota_remaining_below_cutoff" {
		t.Errorf("reason = %q", skips[0].Reason)
	}
	if skips[0].Code != domain.CodeQuotaExhausted {
		t.Errorf("code = %q", skips[0].Code)
	}
}

// TestFilterCutoffBoundaryIsInclusive proves the decision is "Remaining <=
// cutoff" exactly at the limit: used 95/100 == 5% remaining with cutoff 0.05
// blocks.
func TestFilterCutoffBoundaryIsInclusive(t *testing.T) {
	clock := newClock()
	cfg := Config{Cutoff: 0.05, Windows: []WindowSpec{
		{Kind: contracts.WindowShort, Unit: UnitTokens, Limit: 100},
	}, Clock: clock}
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 95))
	f := NewFilter(rec, cfg)
	_, skips := f.Filter(context.Background(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm", Credential: cred},
	}})
	if len(skips) != 1 {
		t.Fatalf("boundary not blocked: skips = %+v", skips)
	}

	// One token fewer (used 94 -> 6% remaining) must NOT block.
	rec2 := NewRecorder(nil, cfg)
	_ = rec2.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 94))
	f2 := NewFilter(rec2, cfg)
	kept, skips2 := f2.Filter(context.Background(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm", Credential: cred},
	}})
	if len(skips2) != 0 || len(kept.Attempts) != 1 {
		t.Fatalf("above-cutoff candidate blocked: %+v %+v", kept, skips2)
	}
}

// TestFilterUnknownLimitFailOpen proves ADR-0011 §2.4: a window with no known
// ceiling never blocks.
func TestFilterUnknownLimitFailOpen(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, Config{Clock: clock}) // default windows, all Limit 0
	cred := domain.CredentialID("acct")
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 1_000_000))
	f := NewFilter(rec, Config{Clock: clock})
	kept, skips := f.Filter(context.Background(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm", Credential: cred},
	}})
	if len(skips) != 0 || len(kept.Attempts) != 1 {
		t.Fatalf("unknown-limit window blocked: %+v %+v", kept, skips)
	}
}

// TestFilterTerminalCredential covers the terminal branch and the cost code.
func TestFilterTerminalCredential(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, Config{Clock: clock})
	cred := domain.CredentialID("acct")
	rec.SetTerminal(cred, domain.CodeQuotaCostCap)
	f := NewFilter(rec, Config{Clock: clock})
	_, skips := f.Filter(context.Background(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm", Credential: cred},
	}})
	if len(skips) != 1 || skips[0].Reason != "quota_terminal" {
		t.Fatalf("terminal not skipped: %+v", skips)
	}
	if skips[0].Code != domain.CodeQuotaCostCap {
		t.Errorf("terminal code = %q", skips[0].Code)
	}
}

// TestFilterZeroCredentialFailOpen covers the "any healthy account" candidate.
func TestFilterZeroCredentialFailOpen(t *testing.T) {
	clock := newClock()
	f := NewFilter(NewRecorder(nil, tokenCfg(clock)), tokenCfg(clock))
	kept, skips := f.Filter(context.Background(), contracts.RoutePlan{Attempts: []contracts.Candidate{
		{Provider: "zai", Model: "glm"}, // zero credential
	}})
	if len(skips) != 0 || len(kept.Attempts) != 1 {
		t.Fatalf("zero-credential candidate blocked: %+v %+v", kept, skips)
	}
}

// TestQuotaCodeCostVsToken covers quotaCode's two branches directly.
func TestQuotaCodeCostVsToken(t *testing.T) {
	if got := quotaCode(contracts.WindowCost); got != domain.CodeQuotaCostCap {
		t.Errorf("cost code = %q", got)
	}
	if got := quotaCode(contracts.WindowShort); got != domain.CodeQuotaExhausted {
		t.Errorf("token code = %q", got)
	}
}

// TestFilterRetryAfter covers the reset-derived cooldown.
func TestFilterRetryAfter(t *testing.T) {
	clock := newClock()
	cred := domain.CredentialID("acct")
	cfg := Config{Clock: clock}
	rec := NewRecorder(nil, cfg)

	// No reader / unknown credential -> 0.
	if got := NewFilter(nil, cfg).RetryAfter(context.Background(), cred); got != 0 {
		t.Errorf("nil reader RetryAfter = %v", got)
	}
	if got := NewFilter(rec, cfg).RetryAfter(context.Background(), ""); got != 0 {
		t.Errorf("empty cred RetryAfter = %v", got)
	}
	if got := NewFilter(rec, cfg).RetryAfter(context.Background(), "ghost"); got != 0 {
		t.Errorf("unknown cred RetryAfter = %v", got)
	}

	// A hint in the future yields the distance to the reset.
	rec.ApplyRetryHint(context.Background(), cred, contracts.WindowShort, clock.Now().Add(30*time.Minute))
	if got := NewFilter(rec, cfg).RetryAfter(context.Background(), cred); got != 30*time.Minute {
		t.Errorf("RetryAfter = %v, want 30m", got)
	}
	// A reset already in the past yields zero.
	clock.advance(time.Hour)
	if got := NewFilter(rec, cfg).RetryAfter(context.Background(), cred); got != 0 {
		t.Errorf("past reset RetryAfter = %v, want 0", got)
	}
}

// TestRecorderIdempotentByAttemptKey proves a re-delivery of the same
// AttemptKey does not double-count: recording twice with the same key keeps the
// window at one usage's worth.
func TestRecorderIdempotentByAttemptKey(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	u := usageInput(cred, "req:1", 30)

	if err := rec.Record(context.Background(), contracts.OutcomeSuccess, u); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := rec.Record(context.Background(), contracts.OutcomeSuccess, u); err != nil {
		t.Fatalf("second Record: %v", err)
	}
	st, ok := rec.Snapshot(context.Background(), cred)
	if !ok {
		t.Fatal("no state after Record")
	}
	w := win(st, contracts.WindowShort)
	if w == nil || w.Used != 30 {
		t.Fatalf("used = %+v, want exactly 30 (no double count)", w)
	}
}

// TestRecorderPartialAbortReplaces proves ADR-0011 §5: an aborted stream reports
// the observed tokens with the SAME key and replaces, not sums.
func TestRecorderPartialAbortReplaces(t *testing.T) {
	clock := newClock()
	per := newFakePersistence()
	rec := NewRecorder(per, tokenCfg(clock))
	cred := domain.CredentialID("acct")

	full := usageInput(cred, "req:1", 50)
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, full)
	partial := usageInput(cred, "req:1", 20)
	partial.Aborted = true
	_ = rec.Record(context.Background(), contracts.OutcomeTransient, partial)

	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 50 {
		t.Fatalf("window used = %+v, want 50 (first application; replay no-op)", w)
	}
	// The durable attempt row reflects the latest quantities.
	got, ok, _ := per.GetAttempt(context.Background(), "req:1")
	if !ok || got.Tokens != 20 {
		t.Fatalf("durable attempt = %+v, want tokens 20 replaced", got)
	}
	if per.outcomes["req:1"] != "aborted" {
		t.Fatalf("durable outcome = %q, want aborted", per.outcomes["req:1"])
	}
}

// TestRecorderDistinctAttemptsSum proves two DIFFERENT attempts both count: a
// failover burns two accounts and two usages.
func TestRecorderDistinctAttemptsSum(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, tokenCfg(clock))
	cred := domain.CredentialID("acct")
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "req:1", 10))
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "req:2", 15))
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 25 {
		t.Fatalf("used = %+v, want 25", w)
	}
}

func TestRecorderEmptyCredentialIsNoop(t *testing.T) {
	rec := NewRecorder(nil, tokenCfg(newClock()))
	if err := rec.Record(context.Background(), contracts.OutcomeSuccess, contracts.Usage{AttemptKey: "k"}); err != nil {
		t.Fatalf("Record with empty credential: %v", err)
	}
	if _, ok := rec.Snapshot(context.Background(), ""); ok {
		t.Fatal("empty credential produced state")
	}
}

// TestRecorderWindowRollover proves a locally tracked window resets when its
// declared duration elapses.
func TestRecorderWindowRollover(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k1", 40))
	// Advance past the short window and record again: the window rolls over.
	clock.advance(shortWindow + time.Minute)
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k2", 10))
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 10 {
		t.Fatalf("used after rollover = %+v, want 10", w)
	}
}

// TestRecorderHeaderWinsOverLocal proves source precedence: once a window is
// header-sourced, a local Record does not advance it.
func TestRecorderHeaderWinsOverLocal(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")

	rec.ApplyHeader(context.Background(), cred, []contracts.QuotaWindow{
		{Kind: contracts.WindowShort, Limit: 100, Used: 80, Remaining: 0.2, Source: contracts.SourceHeader},
	})
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 10))
	st, _ := rec.Snapshot(context.Background(), cred)
	w := win(st, contracts.WindowShort)
	if w == nil || w.Used != 80 || w.Source != contracts.SourceHeader {
		t.Fatalf("header window changed by local record: %+v", w)
	}
}

// TestRecorderRetryHintWinsOverLocal proves a hint re-anchors and zeroes a
// local window and blocks local accrual until re-anchored.
func TestRecorderRetryHintWinsOverLocal(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 10))
	reset := clock.Now().Add(time.Hour)
	rec.ApplyRetryHint(context.Background(), cred, contracts.WindowShort, reset)

	st, _ := rec.Snapshot(context.Background(), cred)
	w := win(st, contracts.WindowShort)
	if w == nil || w.Remaining != 0 || w.Source != contracts.SourceRetryHint || !w.ResetsAt.Equal(reset) {
		t.Fatalf("hint not applied: %+v", w)
	}
	// A local record after the hint must not advance the exhausted window.
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k2", 10))
	st, _ = rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w.Used != 10 {
		t.Fatalf("local record advanced a hinted window: %+v", w)
	}
}

// TestRecorderRetryHintOnHeaderDoesNotOverwrite proves header > retry hint.
func TestRecorderRetryHintOnHeaderDoesNotOverwrite(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	rec.ApplyHeader(context.Background(), cred, []contracts.QuotaWindow{
		{Kind: contracts.WindowShort, Limit: 100, Used: 10, Remaining: 0.9, Source: contracts.SourceHeader},
	})
	rec.ApplyRetryHint(context.Background(), cred, contracts.WindowShort, clock.Now().Add(time.Hour))
	st, _ := rec.Snapshot(context.Background(), cred)
	w := win(st, contracts.WindowShort)
	if w.Source != contracts.SourceHeader || w.Remaining != 0.9 {
		t.Fatalf("hint overwrote a header window: %+v", w)
	}
}

// TestRecorderHeaderCreatesUnknownWindow covers the header-create branch for a
// kind not declared in the config.
func TestRecorderHeaderCreatesUnknownWindow(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock) // only short declared
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	rec.ApplyHeader(context.Background(), cred, []contracts.QuotaWindow{
		{Kind: contracts.WindowLong, Limit: 200, Used: 50, Remaining: 0.75, Source: contracts.SourceHeader},
	})
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowLong); w == nil || w.Used != 50 {
		t.Fatalf("long window not created from header: %+v", w)
	}
}

// TestRecorderRetryHintCreatesWindow covers the hint-create branch.
func TestRecorderRetryHintCreatesWindow(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")
	reset := clock.Now().Add(time.Hour)
	rec.ApplyRetryHint(context.Background(), cred, contracts.WindowLong, reset)
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowLong); w == nil || w.ResetsAt.IsZero() {
		t.Fatalf("long window not created from hint: %+v", w)
	}
}

func TestRecorderApplyHeaderNoops(t *testing.T) {
	rec := NewRecorder(nil, tokenCfg(newClock()))
	rec.ApplyHeader(context.Background(), "", []contracts.QuotaWindow{{Kind: contracts.WindowShort}})
	rec.ApplyHeader(context.Background(), "acct", nil)
	if _, ok := rec.Snapshot(context.Background(), "acct"); ok {
		t.Fatal("ApplyHeader with no windows created state")
	}
}

func TestRecorderApplyRetryHintNoops(t *testing.T) {
	rec := NewRecorder(nil, tokenCfg(newClock()))
	rec.ApplyRetryHint(context.Background(), "", contracts.WindowShort, time.Now().Add(time.Hour))
	rec.ApplyRetryHint(context.Background(), "acct", contracts.WindowShort, time.Time{})
	if _, ok := rec.Snapshot(context.Background(), "acct"); ok {
		t.Fatal("ApplyRetryHint with a zero reset created state")
	}
}

// TestRecorderSetTerminalNoops covers the guard branches.
func TestRecorderSetTerminalNoops(t *testing.T) {
	rec := NewRecorder(nil, tokenCfg(newClock()))
	rec.SetTerminal("", "x")
	rec.SetTerminal("acct", "")
	if _, ok := rec.Snapshot(context.Background(), "acct"); ok {
		t.Fatal("SetTerminal no-op created state")
	}
	// A real terminal on a fresh credential creates state.
	rec.SetTerminal("acct", domain.CodeQuotaCostCap)
	st, ok := rec.Snapshot(context.Background(), "acct")
	if !ok || st.TerminalCode != domain.CodeQuotaCostCap {
		t.Fatalf("terminal state = %+v ok=%v", st, ok)
	}
	// A terminal on an EXISTING credential mutates in place.
	rec.SetTerminal("acct", domain.CodeQuotaInvalidCredential)
	st, _ = rec.Snapshot(context.Background(), "acct")
	if st.TerminalCode != domain.CodeQuotaInvalidCredential {
		t.Fatalf("terminal code not updated: %+v", st)
	}
}

// TestRecorderPersistenceRoundTrip proves the durable load path: a fresh
// recorder over the same persistence sees the persisted windows.
func TestRecorderPersistenceRoundTrip(t *testing.T) {
	clock := newClock()
	per := newFakePersistence()
	cred := domain.CredentialID("acct")
	rec1 := NewRecorder(per, tokenCfg(clock))
	_ = rec1.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 30))

	rec2 := NewRecorder(per, tokenCfg(clock))
	st, ok := rec2.Snapshot(context.Background(), cred)
	if !ok {
		t.Fatal("persisted state not loaded")
	}
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 30 {
		t.Fatalf("loaded window = %+v, want used 30", w)
	}
}

// TestRecorderPersistenceErrorsAreTolerated proves a durable write failure does
// not panic or corrupt the in-memory state (the observer never blocks the
// request path).
func TestRecorderPersistenceErrorsAreTolerated(t *testing.T) {
	clock := newClock()
	per := newFakePersistence()
	per.upsErr = errFake
	per.recErr = errFake
	rec := NewRecorder(per, tokenCfg(clock))
	cred := domain.CredentialID("acct")
	if err := rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput(cred, "k", 10)); err != nil {
		t.Fatalf("Record surfaced a durable error: %v", err)
	}
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 10 {
		t.Fatalf("in-memory state lost on durable error: %+v", w)
	}
}

// TestRecorderPersistenceSnapshotErrorFailOpen proves a failing durable read
// does not produce a state (the filter then fail-opens).
func TestRecorderPersistenceSnapshotErrorFailOpen(t *testing.T) {
	clock := newClock()
	per := newFakePersistence()
	per.snapErr = errFake
	rec := NewRecorder(per, tokenCfg(clock))
	if _, ok := rec.Snapshot(context.Background(), "acct"); ok {
		t.Fatal("failing snapshot produced state")
	}
}

// TestRecorderNoAttemptKeySkipsDurableAttempt covers the empty-key guard.
func TestRecorderNoAttemptKeySkipsDurableAttempt(t *testing.T) {
	clock := newClock()
	per := newFakePersistence()
	rec := NewRecorder(per, tokenCfg(clock))
	cred := domain.CredentialID("acct")
	u := usageInput(cred, "", 10) // no attempt key
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, u)
	if per.attemptCount() != 0 {
		t.Fatal("an empty attempt key was persisted")
	}
	// A replay check with an empty key must not be treated as a replay.
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, u)
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 20 {
		t.Fatalf("empty-key records did not sum: %+v", w)
	}
}

func TestOutcomeName(t *testing.T) {
	if got := outcomeName(contracts.OutcomeSuccess, contracts.Usage{}); got != "ok" {
		t.Errorf("success = %q", got)
	}
	if got := outcomeName(contracts.OutcomeProviderError, contracts.Usage{}); got != "error" {
		t.Errorf("error = %q", got)
	}
	if got := outcomeName(contracts.OutcomeSuccess, contracts.Usage{Aborted: true}); got != "aborted" {
		t.Errorf("aborted = %q", got)
	}
}

// TestSetRemainingClamps covers the clamp branches directly (white-box): a
// negative used would push remaining above 1, and used above limit is clamped.
func TestSetRemainingClamps(t *testing.T) {
	over := &contracts.QuotaWindow{Limit: 100, Used: 150}
	setRemaining(over)
	if over.Used != 100 || over.Remaining != 0 {
		t.Fatalf("over-limit clamp = %+v", over)
	}
	negative := &contracts.QuotaWindow{Limit: 100, Used: -10}
	setRemaining(negative)
	if negative.Remaining != 1 {
		t.Fatalf("negative-used remaining = %v, want clamped to 1", negative.Remaining)
	}
	unknown := &contracts.QuotaWindow{Limit: 0, Used: 42}
	setRemaining(unknown)
	if unknown.Remaining != 1 {
		t.Fatalf("unknown-limit remaining = %v, want 1", unknown.Remaining)
	}
}

// TestRecorderConcurrentRecordsWithPersistenceAreRaceFree is the regression for
// the fusion fan-out race: several goroutines Record the SAME credential through
// a DURABLE persistence, so the window slice is appended under the credential
// lock while another goroutine would otherwise persist it outside that lock.
// Run under -race it fails if persistWindows reads st.Windows unlocked.
func TestRecorderConcurrentRecordsWithPersistenceAreRaceFree(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(newFakePersistence(), cfg)
	cred := domain.CredentialID("acct")

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_ = rec.Record(context.Background(), contracts.OutcomeSuccess,
				usageInput(cred, "k"+string(rune('a'+i%26))+string(rune('0'+i/26)), 1))
		}(i)
	}
	close(start)
	wg.Wait()

	// Every distinct key contributed 1 token, despite the durable writes.
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != n {
		t.Fatalf("concurrent used = %+v, want %d", w, n)
	}
}

// TestRecorderConcurrentRecordAndSnapshotAreRaceFree is the regression for the
// second fusion-fan-out race: a reader (Snapshot, the preflight filter) runs
// concurrently with a writer (Record) on the SAME credential. Run under -race it
// fails if Snapshot clones st.Windows after releasing the credential lock.
func TestRecorderConcurrentRecordAndSnapshotAreRaceFree(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(newFakePersistence(), tokenCfg(clock))
	cred := domain.CredentialID("acct")

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			<-start
			_ = rec.Record(context.Background(), contracts.OutcomeSuccess,
				usageInput(cred, "w"+string(rune('a'+i%26))+string(rune('0'+i/26)), 1))
		}(i)
		go func() {
			defer wg.Done()
			<-start
			_, _ = rec.Snapshot(context.Background(), cred)
		}()
	}
	close(start)
	wg.Wait()
}

// TestRecorderConcurrentRecordsAreRaceFree exercises the per-credential lock
// under -race with distinct attempt keys (so all contributions count).
func TestRecorderConcurrentRecordsAreRaceFree(t *testing.T) {
	clock := newClock()
	cfg := tokenCfg(clock)
	rec := NewRecorder(nil, cfg)
	cred := domain.CredentialID("acct")

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_ = rec.Record(context.Background(), contracts.OutcomeSuccess,
				usageInput(cred, "k"+string(rune('a'+i%26))+string(rune('0'+i/26)), 1))
		}(i)
	}
	close(start)
	wg.Wait()

	// Every distinct key contributed 1 token.
	st, _ := rec.Snapshot(context.Background(), cred)
	if w := win(st, contracts.WindowShort); w == nil || w.Used != n {
		t.Fatalf("concurrent used = %+v, want %d", w, n)
	}
}

// TestRecorderDistinctCredentialsDoNotContend covers separate credential locks.
func TestRecorderDistinctCredentialsDoNotContend(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, tokenCfg(clock))
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput("a", "k1", 5))
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput("b", "k2", 7))
	sa, _ := rec.Snapshot(context.Background(), "a")
	sb, _ := rec.Snapshot(context.Background(), "b")
	if win(sa, contracts.WindowShort).Used != 5 || win(sb, contracts.WindowShort).Used != 7 {
		t.Fatal("credential states leaked into each other")
	}
}

// TestRecorderCloneIsolation proves a Snapshot is a copy: mutating it does not
// change the recorder's state.
func TestRecorderCloneIsolation(t *testing.T) {
	clock := newClock()
	rec := NewRecorder(nil, tokenCfg(clock))
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput("acct", "k", 10))
	st, _ := rec.Snapshot(context.Background(), "acct")
	st.Windows[0].Used = 999
	st2, _ := rec.Snapshot(context.Background(), "acct")
	if st2.Windows[0].Used != 10 {
		t.Fatalf("snapshot mutation leaked: %+v", st2.Windows)
	}
}

// TestRecorderCostWindow covers the UnitCost mapping through a cost window.
func TestRecorderCostWindow(t *testing.T) {
	clock := newClock()
	cfg := Config{
		Windows: []WindowSpec{
			{Kind: contracts.WindowCost, Unit: UnitCost, Limit: 100, Duration: costWindow},
		},
		Clock: clock,
	}
	rec := NewRecorder(nil, cfg)
	u := usageInput("acct", "k", 0)
	u.CostMicros = 60
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, u)
	st, _ := rec.Snapshot(context.Background(), "acct")
	if w := win(st, contracts.WindowCost); w == nil || w.Used != 60 {
		t.Fatalf("cost window = %+v, want used 60", w)
	}
}

// TestUnitRequestsWindow covers the request unit mapping.
func TestUnitRequestsWindow(t *testing.T) {
	clock := newClock()
	cfg := Config{
		Windows: []WindowSpec{{Kind: contracts.WindowShort, Unit: UnitRequests, Limit: 3}},
		Clock:   clock,
	}
	rec := NewRecorder(nil, cfg)
	_ = rec.Record(context.Background(), contracts.OutcomeSuccess, usageInput("acct", "k", 999))
	st, _ := rec.Snapshot(context.Background(), "acct")
	if w := win(st, contracts.WindowShort); w == nil || w.Used != 1 {
		t.Fatalf("requests window = %+v, want used 1", w)
	}
}

// errFake is a sentinel for the injected durable failures.
var errFake = errSentinel("fake")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
