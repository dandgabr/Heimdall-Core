// Package providers holds the provider-family registry (F1.4).
//
// A "family" is the protocol implementation (ADR-0001): immutable, one per wire
// dialect, holding no account state. The registry is the lookup the composition
// root and the auth layer use to turn a ProviderID into a ProviderFamily. It is
// deliberately separate from the concrete families so adding a provider never
// touches the registry.
package providers

import (
	"sort"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Registry maps ProviderID to a ProviderFamily.
//
// DETERMINISM IS A REQUIREMENT: All() must return a stable order across runs
// and machines, so the registry never iterates its map. Names are sorted
// lexicographically; a caller that ranges over All() (e.g. to build the model
// catalog or to pick a default) therefore gets reproducible behaviour.
type Registry struct {
	mu       sync.RWMutex
	families map[domain.ProviderID]contracts.ProviderFamily
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{families: make(map[domain.ProviderID]contracts.ProviderFamily)}
}

// Register adds a family. A nil family, an empty ID or a duplicate ID is
// rejected: a misconfigured composition root must fail loudly at startup rather
// than silently shadow a provider.
func (r *Registry) Register(family contracts.ProviderFamily) error {
	if family == nil {
		return domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "nil family"}),
		)
	}
	id := family.ID()
	if id == "" {
		return domain.New(domain.CodeProviderInvalid,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "empty provider id"}),
		)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.families[id]; exists {
		return domain.New(domain.CodeProviderDuplicate,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	r.families[id] = family
	return nil
}

// Get returns the family for id, or provider.not_found.
func (r *Registry) Get(id domain.ProviderID) (contracts.ProviderFamily, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	family, ok := r.families[id]
	if !ok {
		return nil, domain.New(domain.CodeProviderNotFound,
			domain.WithHTTPStatus(404),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	return family, nil
}

// All returns every family in deterministic (ID-sorted) order.
func (r *Registry) All() []contracts.ProviderFamily {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.families))
	for id := range r.families {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)

	out := make([]contracts.ProviderFamily, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.families[domain.ProviderID(id)])
	}
	return out
}

// IDs returns the registered IDs in deterministic order.
func (r *Registry) IDs() []domain.ProviderID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.families))
	for id := range r.families {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)

	out := make([]domain.ProviderID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.ProviderID(id))
	}
	return out
}

// Has reports whether a family is registered. It satisfies the allowlist check
// the combo validator performs (combos.ProviderSet), keeping the registry as the
// single source of truth for "known provider" (ADR-0013 §3.6 / SEC-10).
func (r *Registry) Has(id domain.ProviderID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.families[id]
	return ok
}

// DeclaresModel reports whether ANY registered family declares the model via
// Capabilities(model) ok=true. A family that does not know the model reports
// ok=false (ADR-0001), so this is exactly "the model is routable".
func (r *Registry) DeclaresModel(model domain.ModelID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, family := range r.families {
		if family == nil {
			continue
		}
		if _, ok := family.Capabilities(model); ok {
			return true
		}
	}
	return false
}
