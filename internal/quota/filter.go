package quota

import (
	"context"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Filter is the preflight quota filter (ADR-0011 §1). It reads the per-credential
// state through a contracts.QuotaStateReader and removes candidates whose
// credential has no usable quota, returning a Skip for each removal so the
// decision is explainable.
//
// # What it blocks
//
// A candidate is removed when ANY of its credential's non-terminal windows has
// Remaining <= cutoff for that window (ADR-0011 §2.3: the most restrictive
// window decides). The decision is on the FRACTION remaining, never on "used > X"
// (ADR-0011 §2.2). A window with an unknown limit (Limit == 0) fail-opens and
// never blocks (ADR-0011 §2.4).
//
// # What it does NOT decide
//
// A candidate with a zero Credential is "any healthy credential of the family"
// (ADR-0009 §1). This filter cannot pick one — that is the Dispatcher's job at
// attempt time — so it fail-opens on such candidates. It is also PURE: it never
// mutates quota and never writes.
type Filter struct {
	cfg    Config
	reader contracts.QuotaStateReader
}

var _ contracts.QuotaFilter = (*Filter)(nil)

// NewFilter builds a Filter over a state reader. A nil reader makes the filter
// a no-op (every candidate survives), which is the documented test default.
func NewFilter(reader contracts.QuotaStateReader, cfg Config) *Filter {
	if cfg.Clock == nil {
		panic("quota: nil clock")
	}
	return &Filter{cfg: cfg.normalise(), reader: reader}
}

// Filter implements contracts.QuotaFilter. It returns the plan with quota-dead
// candidates removed (order otherwise preserved) and the Skips explaining each.
func (f *Filter) Filter(ctx context.Context, plan contracts.RoutePlan) (contracts.RoutePlan, []contracts.Skip) {
	if f.reader == nil {
		return plan, nil
	}
	kept := make([]contracts.Candidate, 0, len(plan.Attempts))
	var skips []contracts.Skip
	for _, c := range plan.Attempts {
		skip, blocked := f.check(ctx, c)
		if blocked {
			skips = append(skips, skip)
			continue
		}
		kept = append(kept, c)
	}
	plan.Attempts = kept
	return plan, skips
}

// check decides one candidate. blocked is true with a Skip when the candidate's
// credential has no usable quota.
func (f *Filter) check(ctx context.Context, c contracts.Candidate) (contracts.Skip, bool) {
	// A zero credential is "any healthy account": this filter cannot evaluate a
	// specific account, so it does not block (the Dispatcher re-checks).
	if c.Credential == "" {
		return contracts.Skip{}, false
	}
	state, ok := f.reader.Snapshot(ctx, c.Credential)
	if !ok {
		// No recorded state: fail-open with a local counter (ADR-0011 §2.4).
		return contracts.Skip{}, false
	}
	if state.TerminalCode != "" {
		return contracts.Skip{
			Candidate: c,
			Reason:    "quota_terminal",
			Code:      state.TerminalCode,
		}, true
	}
	for _, w := range state.Windows {
		// An unknown ceiling never blocks: the counter is observability only.
		if w.Limit <= 0 {
			continue
		}
		if w.Remaining <= f.cfg.cutoffFor(w.Kind) {
			return contracts.Skip{
				Candidate: c,
				Reason:    "quota_remaining_below_cutoff",
				Code:      quotaCode(w.Kind),
			}, true
		}
	}
	return contracts.Skip{}, false
}

// quotaCode maps a blocked window to its i18n code (ADR-0011 §7).
func quotaCode(kind contracts.WindowKind) string {
	if kind == contracts.WindowCost {
		return domain.CodeQuotaCostCap
	}
	return domain.CodeQuotaExhausted
}

// RetryAfter derives the cooldown the Dispatcher should use when a credential is
// quota-blocked (ADR-0011 §6): the distance from now to the latest ResetsAt among
// the credential's windows, or zero when no reset is known (the Dispatcher then
// falls back to the exponential backoff). It never blocks a header with a past
// reset; a reset already passed yields zero.
func (f *Filter) RetryAfter(ctx context.Context, cred domain.CredentialID) time.Duration {
	if f.reader == nil || cred == "" {
		return 0
	}
	state, ok := f.reader.Snapshot(ctx, cred)
	if !ok {
		return 0
	}
	now := f.cfg.Clock.Now()
	var latest time.Time
	for _, w := range state.Windows {
		if w.ResetsAt.After(latest) {
			latest = w.ResetsAt
		}
	}
	if latest.IsZero() || !latest.After(now) {
		return 0
	}
	return latest.Sub(now)
}
