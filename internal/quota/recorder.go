package quota

import (
	"context"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// credState is the recorder's private per-credential state. It embeds the frozen
// contracts.QuotaState (which cannot be extended) and adds the recorder's own
// bookkeeping: whether the durable snapshot has been loaded lazily.
type credState struct {
	contracts.QuotaState
	loaded bool
}

// Recorder is the OBSERVER of Usage (ADR-0011 §1). It receives ONE Usage per
// attempt together with that attempt's outcome and maintains the per-credential
// window state that the Filter reads.
//
// # Idempotency
//
// Every Usage carries a deterministic AttemptKey. Record is idempotent by that
// key: a re-delivery of the same attempt (the sink retried, or an aborted
// stream replacing a full one) REPLACES rather than double-counts. Idempotency
// is enforced by remembering the value applied per key and by an upsert-by-key
// in the durable store, so the window total converges to the latest value for
// that attempt rather than summing replays.
//
// # Concurrency
//
// Record may be called from several attempt goroutines (a failover burns several
// accounts). A per-credential mutex serializes the read-modify-write of that
// credential's windows; different credentials do not contend.
//
// # Durability
//
// When a Persistence is injected, a Record writes the affected windows through
// it (the store's single-writer connection). A nil Persistence keeps everything
// in memory, which is the documented test/compat default.
type Recorder struct {
	cfg Config
	per Persistence

	mu    sync.Mutex
	state map[domain.CredentialID]*credState
	// applied remembers the Usage last applied for an AttemptKey, so a replay
	// with the same key is detected in-memory (and does not re-add deltas).
	applied map[string]contracts.Usage
	// credMu serializes the read-modify-write per credential.
	credMu map[domain.CredentialID]*sync.Mutex
}

var (
	_ contracts.UsageRecorder    = (*Recorder)(nil)
	_ contracts.QuotaStateReader = (*Recorder)(nil)
)

// NewRecorder builds a Recorder. per may be nil (memory-only). A nil clock
// panics at construction (programming error).
func NewRecorder(per Persistence, cfg Config) *Recorder {
	if cfg.Clock == nil {
		panic("quota: nil clock")
	}
	return &Recorder{
		cfg:     cfg.normalise(),
		per:     per,
		state:   make(map[domain.CredentialID]*credState),
		applied: make(map[string]contracts.Usage),
		credMu:  make(map[domain.CredentialID]*sync.Mutex),
	}
}

// lockCred returns the per-credential mutex, creating it on first use.
func (r *Recorder) lockCred(cred domain.CredentialID) *sync.Mutex {
	r.mu.Lock()
	m := r.credMu[cred]
	if m == nil {
		m = &sync.Mutex{}
		r.credMu[cred] = m
	}
	r.mu.Unlock()
	return m
}

// Record applies one Usage under the given attempt outcome. outcome is kept
// only for the durable attempt log (ok|error|aborted); the window arithmetic is
// driven by the Usage quantities.
func (r *Recorder) Record(ctx context.Context, outcome contracts.AttemptOutcome, u contracts.Usage) error {
	if u.Credential == "" {
		return nil
	}

	// Apply, persist and mark under the per-credential lock. Persisting outside
	// it would iterate st.Windows while a concurrent Record of the SAME
	// credential appends to it under the lock (a data race — exercised by the
	// fusion fan-out, which records several panels of one account in parallel).
	// Holding the lock also makes the idempotency check-then-apply atomic for a
	// key (the same AttemptKey always names the same credential), so two
	// concurrent replays cannot both add their delta.
	m := r.lockCred(u.Credential)
	m.Lock()

	// Idempotency gate: a key already applied is a replay. Reapplying is a
	// no-op for the window total (the first application already contributed its
	// quantity), so a retry of the sink cannot double-count.
	r.mu.Lock()
	_, seen := r.applied[u.AttemptKey]
	r.mu.Unlock()
	if seen && u.AttemptKey != "" {
		m.Unlock()
		// Refresh the durable attempt row so the latest quantities are persisted
		// (replace, not sum), but do NOT touch the window totals.
		r.persistAttempt(ctx, outcome, u)
		return nil
	}

	st := r.stateLocked(ctx, u.Credential)
	r.applyLocked(st, u)
	r.persistWindows(ctx, st)

	if u.AttemptKey != "" {
		r.mu.Lock()
		r.applied[u.AttemptKey] = u
		r.mu.Unlock()
	}
	m.Unlock()

	r.persistAttempt(ctx, outcome, u)
	return nil
}

// stateLocked returns the credential's state, loading lazily from the durable
// store on first touch. The caller holds the credential lock, so the in-memory
// map access is safe against other Records of the same credential.
func (r *Recorder) stateLocked(ctx context.Context, cred domain.CredentialID) *credState {
	r.mu.Lock()
	st := r.state[cred]
	if st == nil {
		st = &credState{QuotaState: contracts.QuotaState{Credential: cred}}
		r.state[cred] = st
	}
	if !st.loaded {
		st.loaded = true
		if r.per != nil {
			if persisted, ok, err := r.per.Snapshot(ctx, cred); err == nil && ok {
				st.Windows = persisted.Windows
				st.TerminalCode = persisted.TerminalCode
			}
		}
	}
	r.mu.Unlock()
	return st
}

// applyLocked folds one Usage into the credential's windows. The caller holds
// the credential lock.
func (r *Recorder) applyLocked(st *credState, u contracts.Usage) {
	now := r.cfg.Clock.Now()
	for _, spec := range r.cfg.Windows {
		w := st.window(spec.Kind)
		if w == nil {
			created := contracts.QuotaWindow{
				Kind:      spec.Kind,
				Limit:     spec.Limit,
				Remaining: 1,
				Source:    contracts.SourceLocalCounter,
				UpdatedAt: now,
			}
			// A locally tracked window estimates its reset from the declared
			// duration, so it rolls over instead of accumulating forever.
			if spec.Duration > 0 {
				created.ResetsAt = now.Add(spec.Duration)
			}
			st.Windows = append(st.Windows, created)
			w = &st.Windows[len(st.Windows)-1]
		}
		// A locally observed window rolls over when its reset has passed.
		if !w.ResetsAt.IsZero() && !now.Before(w.ResetsAt) {
			w.Used = 0
			w.ResetsAt = now.Add(spec.Duration)
		}
		// The local counter only advances a window whose freshest source is not
		// a more authoritative header or hint (header > hint > local, ADR-0011
		// §3).
		if w.Source == contracts.SourceHeader || w.Source == contracts.SourceRetryHint {
			continue
		}
		w.Used += spec.Unit.value(u)
		w.Source = contracts.SourceLocalCounter
		w.UpdatedAt = now
		setRemaining(w)
	}
}

// setRemaining recomputes the Remaining fraction from Used/Limit. Unknown limit
// fail-opens with Remaining 1.0.
func setRemaining(w *contracts.QuotaWindow) {
	if w.Limit > 0 {
		if w.Used > w.Limit {
			w.Used = w.Limit
		}
		// Compute the remaining FRACTION as (limit-used)/limit, not 1-used/limit:
		// the latter subtracts a rounded quotient and can round the boundary
		// value UP (e.g. 95/100 gives 0.050000000000000044), which would make
		// `Remaining <= cutoff` miss the exact boundary the ADR specifies. The
		// subtraction-free form is correctly rounded and hits the equality.
		// Used was clamped to Limit above, so this is in [0,1]; the lower clamp
		// is defensive against a negative Used (also bounded by the caller).
		w.Remaining = (w.Limit - w.Used) / w.Limit
		if w.Remaining > 1 {
			w.Remaining = 1
		}
		return
	}
	w.Remaining = 1
}

// ApplyHeader folds passive upstream header values into a credential's state
// (ADR-0011 §3.1). The slice carries the header's absolute view. It is exported
// so the Dispatcher can feed `x-ratelimit-*` without this package knowing HTTP.
func (r *Recorder) ApplyHeader(ctx context.Context, cred domain.CredentialID, windows []contracts.QuotaWindow) {
	if cred == "" || len(windows) == 0 {
		return
	}
	m := r.lockCred(cred)
	m.Lock()
	st := r.stateLocked(ctx, cred)
	now := r.cfg.Clock.Now()
	for _, hw := range windows {
		w := st.window(hw.Kind)
		if w == nil {
			st.Windows = append(st.Windows, contracts.QuotaWindow{Kind: hw.Kind})
			w = &st.Windows[len(st.Windows)-1]
		}
		w.Limit = hw.Limit
		w.Used = hw.Used
		w.Remaining = hw.Remaining
		w.ResetsAt = hw.ResetsAt
		w.Source = contracts.SourceHeader
		w.UpdatedAt = now
	}
	r.persistWindows(ctx, st)
	m.Unlock()
}

// ApplyRetryHint re-anchors a window's ResetsAt from a 429 Retry-After/reset
// (ADR-0011 §3.3): the account is exhausted until the reset, so Remaining drops
// to 0 for that window. It is the most direct "exhausted until here" signal.
// A header-sourced window is authoritative and is NOT overwritten (header >
// retry hint).
func (r *Recorder) ApplyRetryHint(ctx context.Context, cred domain.CredentialID, kind contracts.WindowKind, resetsAt time.Time) {
	if cred == "" || resetsAt.IsZero() {
		return
	}
	m := r.lockCred(cred)
	m.Lock()
	st := r.stateLocked(ctx, cred)
	w := st.window(kind)
	if w == nil {
		st.Windows = append(st.Windows, contracts.QuotaWindow{Kind: kind})
		w = &st.Windows[len(st.Windows)-1]
	}
	if w.Source != contracts.SourceHeader {
		w.ResetsAt = resetsAt
		w.Remaining = 0
		w.Source = contracts.SourceRetryHint
		w.UpdatedAt = r.cfg.Clock.Now()
	}
	r.persistWindows(ctx, st)
	m.Unlock()
}

// Snapshot returns the current state of a credential, loading it lazily. ok is
// false when the credential has no recorded state (the filter fail-opens).
func (r *Recorder) Snapshot(ctx context.Context, cred domain.CredentialID) (contracts.QuotaState, bool) {
	if cred == "" {
		return contracts.QuotaState{}, false
	}
	// The lock is held through the read AND the clone: a concurrent Record of
	// the same credential appends to st.Windows under this lock, so releasing it
	// before cloning would let a reader observe a slice mid-append (a data race,
	// exercised by the fusion fan-out which reads the filter while recording).
	m := r.lockCred(cred)
	m.Lock()
	defer m.Unlock()
	st := r.stateLocked(ctx, cred)
	if len(st.Windows) == 0 && st.TerminalCode == "" {
		return contracts.QuotaState{}, false
	}
	return st.clone(), true
}

// SetTerminal marks a credential's quota terminal (unrecoverable by waiting,
// ADR-0011 §2.5). A terminal state is distinct from "window exhausted".
func (r *Recorder) SetTerminal(cred domain.CredentialID, code string) {
	if cred == "" || code == "" {
		return
	}
	m := r.lockCred(cred)
	m.Lock()
	r.mu.Lock()
	st := r.state[cred]
	if st == nil {
		st = &credState{QuotaState: contracts.QuotaState{Credential: cred}, loaded: true}
		r.state[cred] = st
	}
	st.TerminalCode = code
	r.mu.Unlock()
	m.Unlock()
}

// persistWindows writes every window of a state through the durable port.
func (r *Recorder) persistWindows(ctx context.Context, st *credState) {
	if r.per == nil {
		return
	}
	for _, w := range st.Windows {
		_ = r.per.UpsertWindow(ctx, st.Credential, w)
	}
}

// persistAttempt writes one attempt row through the durable port.
func (r *Recorder) persistAttempt(ctx context.Context, outcome contracts.AttemptOutcome, u contracts.Usage) {
	if r.per == nil || u.AttemptKey == "" {
		return
	}
	_, _ = r.per.RecordAttempt(ctx, u, outcomeName(outcome, u))
}

// outcomeName names the durable outcome. An aborted stream is reported as
// "aborted" so an audit can tell a partial use from a clean one (ADR-0011 §5).
func outcomeName(o contracts.AttemptOutcome, u contracts.Usage) string {
	if u.Aborted {
		return "aborted"
	}
	switch o {
	case contracts.OutcomeSuccess:
		return "ok"
	default:
		return "error"
	}
}

// window returns a pointer to the window of a kind, or nil.
func (st *credState) window(kind contracts.WindowKind) *contracts.QuotaWindow {
	for i := range st.Windows {
		if st.Windows[i].Kind == kind {
			return &st.Windows[i]
		}
	}
	return nil
}

// clone returns a deep copy so a reader cannot mutate the recorder's state
// through a shared slice header.
func (st *credState) clone() contracts.QuotaState {
	out := contracts.QuotaState{Credential: st.Credential, TerminalCode: st.TerminalCode}
	out.Windows = make([]contracts.QuotaWindow, len(st.Windows))
	copy(out.Windows, st.Windows)
	return out
}
