// Package quota implements the quota filter and the usage recorder of F3
// (ADR-0011).
//
// # Position
//
// Quota is NOT a gate. The Filter runs in the PREFLIGHT (the Router consumes it
// when building the RoutePlan and the Dispatcher consults it before each
// attempt); the Recorder is the OBSERVER that updates the state the Filter
// reads. Neither is a contracts.Gate.
//
// # Unit of quota: per CREDENTIAL
//
// The state is indexed by domain.CredentialID (ADR-0001), never by provider:
// two accounts of the same family have independent quotas. Quota exhausted is
// therefore a ScopeCredential condition — it cools down the ACCOUNT until its
// reset, and it NEVER opens the provider's circuit (ADR-0011 §6).
//
// # The decision is `% remaining <= cutoff`, not `used > X`
//
// Every window carries a Remaining fraction in [0,1]; the Filter blocks a
// candidate when any of its non-terminal windows has Remaining <= cutoff. A
// comparison on absolute "used" is rejected because the ceiling varies per plan
// and breaks when the limit is unknown (ADR-0011 §2.2). An unknown limit
// (Limit == 0) fail-opens: the window never blocks.
//
// # Durable vs ephemeral
//
// Local counters and a window's ResetsAt are DURABLE (SQLite WAL) so a restart
// cannot forget that the short window was spent; per-credential in-flight
// pressure is ephemeral. The Recorder writes through an injected Persistence
// port so the package is testable without SQLite and the store stays the only
// thing that knows SQLite.
//
// # Source precedence
//
// Header > RetryHint > LocalCounter (ADR-0011 §3). A header-sourced window is
// authoritative for its fraction and a local Record does not overwrite it; a
// RetryHint re-anchors ResetsAt and zeroes Remaining (the account is exhausted
// until the reset). The local counter is the fallback and the only signal when
// the provider exposes no quota.
package quota

import (
	"context"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Unit is the quantity a window measures. It is what maps a Usage onto a
// window's Used counter; mixing units in one window would be meaningless, so
// each window declares exactly one.
type Unit uint8

const (
	// UnitTokens counts total tokens (input+output).
	UnitTokens Unit = iota
	// UnitRequests counts upstream requests.
	UnitRequests
	// UnitCost counts estimated cost in micro-units.
	UnitCost
)

// value extracts the window's quantity from a Usage.
func (u Unit) value(usage contracts.Usage) float64 {
	switch u {
	case UnitTokens:
		return float64(usage.Tokens)
	case UnitRequests:
		return float64(usage.Requests)
	case UnitCost:
		return float64(usage.CostMicros)
	default:
		return 0
	}
}

// Default window durations. The operator may declare a ceiling (Limit); the
// duration only decides when a locally-tracked window rolls over when the
// upstream gives no reset. They mirror the ADR's example (~5h / ~7d).
const (
	shortWindow = 5 * time.Hour
	longWindow  = 7 * 24 * time.Hour
	costWindow  = 7 * 24 * time.Hour
)

// WindowSpec declares one quota window the Recorder maintains for every
// credential. Limit == 0 means the ceiling is UNKNOWN; the window is then a
// local counter for observability and never blocks (ADR-0011 §2.4).
type WindowSpec struct {
	Kind     contracts.WindowKind
	Unit     Unit
	Limit    float64
	Duration time.Duration
}

// DefaultWindows are the windows of a subscription with a short (~5h) and a long
// (~7d) token window plus a cost cap, none with a known ceiling. An operator
// declaring a ceiling overrides the Limit through Config.
func DefaultWindows() []WindowSpec {
	return []WindowSpec{
		{Kind: contracts.WindowShort, Unit: UnitTokens, Duration: shortWindow},
		{Kind: contracts.WindowLong, Unit: UnitTokens, Duration: longWindow},
		{Kind: contracts.WindowCost, Unit: UnitCost, Duration: costWindow},
	}
}

// DefaultCutoff reserves the last 5% of a window before the filter blocks. It is
// a FRACTION, so it works even when the ceiling is estimated.
const DefaultCutoff = 0.05

// Config tunes the Filter and the Recorder. The zero value is materialised by
// DefaultConfig, so a caller that only wants behaviour is not forced to pick
// numbers.
type Config struct {
	// Cutoff is the fraction of a window reserved before the filter blocks:
	// Remaining <= Cutoff is a Skip. It must be in [0,1].
	Cutoff float64
	// Cutoffs overrides the cutoff per window kind (ADR-0011 §2.2: "o cutoff é
	// configurável por janela"). A missing kind uses Cutoff.
	Cutoffs map[contracts.WindowKind]float64
	// Windows are the windows the Recorder maintains. Empty means DefaultWindows.
	Windows []WindowSpec
	// Clock is the injectable time source (window resets, RetryAfter anchoring).
	Clock contracts.Clock
}

// DefaultConfig returns the documented defaults over the given clock.
func DefaultConfig(clock contracts.Clock) Config {
	return Config{Cutoff: DefaultCutoff, Windows: DefaultWindows(), Clock: clock}
}

// normalise fills zero fields with defaults so a partial Config is safe. A
// Cutoff outside [0,1] is clamped, never allowed to make every candidate
// eligible (negative) or none (over 1).
func (c Config) normalise() Config {
	def := DefaultConfig(c.Clock)
	if c.Cutoff < 0 {
		c.Cutoff = 0
	}
	if c.Cutoff > 1 {
		c.Cutoff = 1
	}
	if len(c.Windows) == 0 {
		c.Windows = def.Windows
	}
	return c
}

// cutoffFor returns the cutoff of a window kind.
func (c Config) cutoffFor(k contracts.WindowKind) float64 {
	if c.Cutoffs != nil {
		if v, ok := c.Cutoffs[k]; ok {
			return v
		}
	}
	return c.Cutoff
}

// specFor returns the declared spec for a window kind, or a zero spec with
// ok=false. A reading from a header may arrive for a kind the operator did not
// declare; the recorder creates it on the fly with a default duration.
func (c Config) specFor(k contracts.WindowKind) (WindowSpec, bool) {
	for _, s := range c.Windows {
		if s.Kind == k {
			return s, true
		}
	}
	return WindowSpec{Kind: k, Unit: UnitTokens, Duration: shortWindow}, false
}

// Persistence is the durable half of the recorder (ADR-0011 §4): the local
// counters and a window's ResetsAt must survive a restart. *store.QuotaStore
// satisfies it. A nil Persistence makes the Recorder purely in-memory (tests).
type Persistence interface {
	// Snapshot loads one credential's persisted windows.
	Snapshot(ctx context.Context, cred domain.CredentialID) (contracts.QuotaState, bool, error)
	// UpsertWindow stores one window.
	UpsertWindow(ctx context.Context, cred domain.CredentialID, w contracts.QuotaWindow) error
	// GetAttempt reads one usage attempt by its idempotency key.
	GetAttempt(ctx context.Context, key string) (contracts.Usage, bool, error)
	// RecordAttempt stores one usage attempt by its idempotency key
	// (idempotent: the same key replaces, never duplicates).
	RecordAttempt(ctx context.Context, u contracts.Usage, outcome string) (bool, error)
}
