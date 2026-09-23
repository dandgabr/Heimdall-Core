package contracts

import (
	"context"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the quota contract of F3 (ADR-0011). Quota is NOT a gate
// (ADR-0009 §revisão nº 2): a QuotaFilter runs in the PREFLIGHT and the
// UsageRecorder observes. The state lives per CREDENTIAL (ADR-0001), never per
// provider: two accounts of the same family have independent quotas.
//
// Anti-cycle rule (unchanged): this file imports only internal/domain and the
// standard library.

// WindowKind identifies one quota window of a credential. A plan with a ~5h
// window and a ~7d window has two windows; the Cost window caps spend.
type WindowKind uint8

const (
	// WindowShort is the short rolling window (e.g. ~5h).
	WindowShort WindowKind = iota
	// WindowLong is the long rolling window (e.g. ~7d).
	WindowLong
	// WindowCost is the spend cap window.
	WindowCost
)

func (k WindowKind) String() string {
	switch k {
	case WindowShort:
		return "short"
	case WindowLong:
		return "long"
	case WindowCost:
		return "cost"
	default:
		return "unknown"
	}
}

// QuotaSource records where a window's numbers came from, by order of trust:
// Header > RetryHint > LocalCounter (ADR-0011 §3). It is persisted for audit.
type QuotaSource uint8

const (
	// SourceLocalCounter is the fallback local counter (tokens/requests/cost
	// observed); subject to drift, so it estimates with a cutoff margin.
	SourceLocalCounter QuotaSource = iota
	// SourceRetryHint is a 429 Retry-After/reset that re-anchors ResetsAt.
	SourceRetryHint
	// SourceHeader is a passive upstream header (most authoritative, free).
	SourceHeader
)

func (s QuotaSource) String() string {
	switch s {
	case SourceLocalCounter:
		return "local_counter"
	case SourceRetryHint:
		return "retry_hint"
	case SourceHeader:
		return "header"
	default:
		return "unknown"
	}
}

// QuotaWindow is one limit window of ONE credential. Remaining is the fraction
// in [0,1] and is what the filter decides on (Remaining <= cutoff blocks); a
// comparison on absolute "Used > X" is rejected because X varies per plan and
// breaks when the limit is unknown (ADR-0011 §2.2).
type QuotaWindow struct {
	Kind WindowKind
	// Limit is the window ceiling (tokens, requests or cost micros). 0 means
	// the limit is UNKNOWN: the filter fail-opens on this window and the counter
	// is for observability only.
	Limit float64
	// Used is what was consumed in the window.
	Used float64
	// Remaining is the fraction left in [0,1] when Limit is known; 1.0 when the
	// limit is unknown (fail-open).
	Remaining float64
	// ResetsAt is when the window resets; zero means unknown.
	ResetsAt time.Time
	Source   QuotaSource
	// UpdatedAt is when the window was last observed.
	UpdatedAt time.Time
}

// QuotaState is the per-credential state: the windows plus a terminal marker.
type QuotaState struct {
	Credential domain.CredentialID
	Windows    []QuotaWindow
	// TerminalCode is non-empty when the credential's quota is unrecoverable by
	// waiting (e.g. a cancelled plan with no reset). It is distinct from "window
	// exhausted": a terminal state is treated as an invalid credential
	// (ADR-0002 §2), not as a cooldown (ADR-0011 §2.5).
	TerminalCode string
}

// Skip explains why a candidate was filtered. It becomes observability and
// Candidate.Reason; it is never an instruction.
type Skip struct {
	Candidate Candidate
	// Reason is the human-readable cause ("quota_remaining_below_cutoff",
	// "breaker_open", ...).
	Reason string
	// Code is the i18n code (quota.* or the last Record's code).
	Code string
}

// QuotaFilter runs in the PREFLIGHT: the Router consumes it when building the
// RoutePlan and the Dispatcher consults it before each attempt. It is PURE over
// the state it reads (it does not mutate quota) and is NOT a content gate.
type QuotaFilter interface {
	// Filter returns the plan with candidates without quota removed (or demoted
	// per the strategy, ADR-0009 §2) plus the Skips explaining each removal.
	Filter(ctx context.Context, plan RoutePlan) (RoutePlan, []Skip)
}

// QuotaStateReader is the read side the QuotaFilter and the Router use to
// inspect a credential's quota without mutating it. It is separate from the
// UsageRecorder so a consumer can read state without the write capability.
type QuotaStateReader interface {
	// Snapshot returns the current state of a credential; ok=false when the
	// credential has no recorded state (which the filter treats as fail-open).
	Snapshot(ctx context.Context, cred domain.CredentialID) (QuotaState, bool)
}

// UsageRecorder is the OBSERVER of Usage (ADR-0011 §1): it receives ONE Usage
// per attempt together with that attempt's outcome, and maintains the state the
// QuotaFilter reads. It is idempotent by Usage.AttemptKey and never blocks the
// request path. A nil recorder means "no accounting".
type UsageRecorder interface {
	// Record applies one Usage under the given attempt outcome. It is
	// idempotent by Usage.AttemptKey: a re-delivery (or an aborted stream
	// replacing a full one) replaces, never double-counts.
	Record(ctx context.Context, outcome AttemptOutcome, u Usage) error
	// Snapshot returns the current state of a credential (the QuotaFilter reads
	// from here).
	Snapshot(ctx context.Context, cred domain.CredentialID) (QuotaState, bool)
}
