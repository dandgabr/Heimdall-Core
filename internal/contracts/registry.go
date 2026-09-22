package contracts

import (
	"fmt"
	"sort"
	"sync"
)

// This file provides the gate registry. Registering a gate is a composition-root
// concern (internal/app), so the registry itself is a small, concurrency-safe
// value in the contracts package.
//
// DETERMINISM IS A REQUIREMENT: gate execution order must be reproducible across
// runs and machines. The registry therefore never iterates a Go map to produce
// an order; it sorts by name and breaks ties deterministically, because Go map
// iteration order is randomised by design. A chain whose order came from a map
// would produce different prompt-cache keys on two runs of the same config.

// GateFactory builds a gate instance. It is a plain function type so the
// registry holds no dependency on a concrete gate package (anti-cycle) and a
// future WASM loader can satisfy the same type.
type GateFactory func() Gate

// GateRegistry is the named registry of gate factories. The zero value is not
// usable; call NewGateRegistry.
type GateRegistry struct {
	mu        sync.RWMutex
	factories map[string]GateFactory
}

// NewGateRegistry returns an empty registry.
func NewGateRegistry() *GateRegistry {
	return &GateRegistry{factories: make(map[string]GateFactory)}
}

// RegisterGate adds a factory under name. A duplicate name is rejected rather
// than silently overwritten, so a misconfigured composition root fails loudly at
// startup instead of losing a gate.
func (r *GateRegistry) RegisterGate(name string, factory GateFactory) error {
	if name == "" {
		return fmt.Errorf("contracts: gate name must not be empty")
	}
	if factory == nil {
		return fmt.Errorf("contracts: gate %q has a nil factory", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("contracts: gate %q already registered", name)
	}
	r.factories[name] = factory
	return nil
}

// Names returns the registered names in lexicographic order. The sort is what
// makes downstream behaviour deterministic.
func (r *GateRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Factories returns the factories in name order, so a caller that ranges over
// the result gets the deterministic order without any map iteration.
func (r *GateRegistry) Factories() []GateFactory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]GateFactory, 0, len(names))
	for _, name := range names {
		out = append(out, r.factories[name])
	}
	return out
}

// Build instantiates every registered gate in name order. It fails on the first
// factory that does not return a gate or returns a gate whose ID does not match
// its registration name: the name is the registry contract, the ID is the
// runtime identity, and letting them diverge would break logging and dedup.
func (r *GateRegistry) Build() ([]Gate, error) {
	names := r.Names()
	gates := make([]Gate, 0, len(names))
	for _, name := range names {
		r.mu.RLock()
		factory := r.factories[name]
		r.mu.RUnlock()
		g := factory()
		if g == nil {
			return nil, fmt.Errorf("contracts: gate %q factory returned nil", name)
		}
		if g.ID() != name {
			return nil, fmt.Errorf("contracts: gate registered as %q reports ID %q", name, g.ID())
		}
		if g.Stages().Empty() {
			return nil, fmt.Errorf("contracts: gate %q declares no stage", name)
		}
		gates = append(gates, g)
	}
	return gates, nil
}
