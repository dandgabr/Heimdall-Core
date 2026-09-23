package token

import (
	"sort"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Registry is the deterministic registry of compression engines (ADR-0015 §1).
// It validates each engine's mandatory metadata at registration: an engine is
// RECUSED when it omits the declaration, when it is `lossy` AND `ImpactNone`
// (self-contradictory), or when it is `ImpactHigh` without the operator's
// opt-in.
//
// Like the gate registry, it never iterates a map to produce an order: Enabled
// returns the engines sorted by ID, so the boot audit and the compression
// sequence are reproducible.
type Registry struct {
	byID map[string]CompressionEngine
	// allowPrefix maps an engine ID to the operator's opt-in for prefix rewrite
	// (ADR-0015 §3).
	allowPrefix map[string]bool
}

// NewRegistry returns an empty engine registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]CompressionEngine{}, allowPrefix: map[string]bool{}}
}

// Register adds an engine, applying the ADR-0015 §1 validation. allowPrefix is
// the operator's opt-in for THIS engine; it is refused when the engine does not
// declare ImpactHigh (opt-in without effect is a lying config, §3).
func (r *Registry) Register(e CompressionEngine, allowPrefix bool) error {
	if e == nil {
		return bootError("engine is nil", "")
	}
	id := e.ID()
	if id == "" {
		return bootError("engine id must not be empty", "")
	}
	if _, dup := r.byID[id]; dup {
		return bootError("engine "+id+" is already registered", id)
	}
	// The declaration is mandatory: a lossy engine cannot claim to change
	// nothing (ADR-0015 §1).
	if e.Lossy() && e.CacheImpact() == ImpactNone {
		return bootError("engine "+id+" is lossy but declares ImpactNone", id)
	}
	if e.CacheImpact() > ImpactHigh {
		return bootError("engine "+id+" declares an unknown cache impact", id)
	}
	// Opt-in only makes sense for an ImpactHigh engine (ADR-0015 §3).
	if allowPrefix && e.CacheImpact() != ImpactHigh {
		return bootError("engine "+id+" has prefix-rewrite opt-in but is not ImpactHigh", id)
	}

	r.byID[id] = e
	r.allowPrefix[id] = allowPrefix
	return nil
}

// Enabled returns the registered engines in deterministic (ID) order.
func (r *Registry) Enabled() []CompressionEngine {
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]CompressionEngine, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.byID[id])
	}
	return out
}

// AllowPrefixRewrite reports whether the operator opted this engine into prefix
// rewrite.
func (r *Registry) AllowPrefixRewrite(id string) bool { return r.allowPrefix[id] }

// bootError is a wiring error: error.internal, because a bad engine registration
// is a bug in the binary, never the operator's request.
func bootError(reason, engine string) error {
	params := map[string]string{"reason": reason}
	if engine != "" {
		params["engine"] = engine
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(500),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(params),
	)
}
