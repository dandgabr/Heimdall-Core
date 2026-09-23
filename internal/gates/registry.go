package gates

import (
	"sort"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file implements the gate ENGINE of ADR-0014: the deterministic registry
// of built-in gates, the dependency graph derived from each gate's declared
// reads/writes, the per-stage topological order with cycle rejection, and the
// per-gate failure-policy validation.
//
// It is the COMPOSITION-TIME half of the gate pipeline: it validates and ORDERS
// gates at boot. The runtime half (running the ordered gates per stage) stays in
// internal/pipeline. The two are joined by the ordered slices Registry.Build
// emits.
//
// DETERMINISM: the order is a function of the registrations only. It is never
// derived by iterating a Go map (randomised by design); the topological sort
// always breaks ties by gate ID (ADR-0014 §1.3, ADR-SEC-04 §1).

// Factory builds one gate instance. It mirrors contracts.GateFactory so the
// registry works with the frozen type without importing a concrete gate.
type Factory = contracts.GateFactory

// Order is the computed, frozen execution order for the three stages plus the
// full set. It is produced once at boot and never recomputed on the request path
// (ADR-0014 §1).
type Order struct {
	// PreRequest are the gates acting in the pre-request stage, in graph order.
	PreRequest []contracts.Gate
	// OnResponseChunk are the gates acting in the chunk stage, in graph order.
	OnResponseChunk []contracts.Gate
	// PostResponse are the gates acting in the post-response stage, in graph order.
	PostResponse []contracts.Gate
	// All is every built gate in ID order, for Close and the boot audit log.
	All []contracts.Gate
}

// Registry is the boot-time gate registry. It is built once and then read; it is
// NOT concurrency-safe because the boot is single-threaded before serving.
type Registry struct {
	names    map[string]bool
	gates    []contracts.Gate
	declared map[string]contracts.Declared
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{names: map[string]bool{}, declared: map[string]contracts.Declared{}}
}

// RegisterGate adds one gate by name. It rejects duplicates, a nil gate, an
// empty name, a gate whose ID diverges from its registration name, a gate with
// no declared stage, a declared graph that does not match Stages(), and an
// incoherent failure policy — all at boot, before serving (ADR-0014 §5,
// ADR-SEC-03 §4).
func (r *Registry) RegisterGate(name string, factory Factory) error {
	if strings.TrimSpace(name) == "" {
		return bootError("gate name must not be empty", nil)
	}
	if factory == nil {
		return bootError("gate "+name+" has a nil factory", nil)
	}
	if r.names[name] {
		return bootError("gate "+name+" is already registered", nil)
	}
	g := factory()
	if g == nil {
		return bootError("gate "+name+" factory returned nil", nil)
	}
	if g.ID() != name {
		return bootError("gate registered as "+name+" reports ID "+g.ID(), nil)
	}
	if g.Stages().Empty() {
		return bootError("gate "+name+" declares no stage", nil)
	}

	declared := contracts.Declared{Stages: g.Stages()}
	if d, ok := g.(contracts.GateDeclarer); ok {
		declared = d.Declare()
		// The declared stages must equal the contract's Stages(); a gate that
		// declared a different set would be ordered for a stage it does not act
		// in, or run unordered in one it does.
		if declared.Stages != g.Stages() {
			return bootError("gate "+name+" declares stages that do not match Stages()", nil)
		}
	}
	// FailOpen must not mask security: a gate that WRITES pii or injection_flag
	// with FailOpen contradicts its own effect (ADR-0014 §3.4).
	if g.FailurePolicy() == contracts.FailOpen && writesSecurityField(declared.Writes) {
		return bootError("gate "+name+" writes a security field but is FailOpen", nil)
	}
	// A post-response-ONLY gate is always FailOpen by contract (§2): a
	// FailClosed declaration there is incoherent.
	if isPostOnly(declared.Stages) && g.FailurePolicy() == contracts.FailClosed {
		return bootError("gate "+name+" is a FailClosed post-response-only gate", nil)
	}

	r.names[name] = true
	r.gates = append(r.gates, g)
	r.declared[name] = declared
	return nil
}

// Build validates the whole graph, computes the per-stage order once, and
// returns it frozen. A cycle in any stage is rejected here, at boot (ADR-0014
// §1.4): a cycle is always a wiring bug, never something to discover under
// traffic.
func (r *Registry) Build() (Order, error) {
	names := make([]string, 0, len(r.gates))
	for _, g := range r.gates {
		names = append(names, g.ID())
	}
	sort.Strings(names)

	// Every explicit After target must resolve.
	for _, name := range names {
		for _, dep := range r.declared[name].After {
			if !r.names[dep] {
				return Order{}, bootError("gate "+name+" declares After["+dep+"] which is not registered", nil)
			}
		}
	}

	pre, err := r.orderStage(contracts.StagePreRequest)
	if err != nil {
		return Order{}, err
	}
	chunk, err := r.orderStage(contracts.StageOnResponseChunk)
	if err != nil {
		return Order{}, err
	}
	post, err := r.orderStage(contracts.StagePostResponse)
	if err != nil {
		return Order{}, err
	}

	byID := make(map[string]contracts.Gate, len(r.gates))
	for _, g := range r.gates {
		byID[g.ID()] = g
	}
	all := make([]contracts.Gate, 0, len(names))
	for _, name := range names {
		all = append(all, byID[name])
	}
	return Order{PreRequest: pre, OnResponseChunk: chunk, PostResponse: post, All: all}, nil
}

// orderStage runs Kahn's algorithm over the edges of ONE stage, breaking ties by
// gate ID. Nodes are the gates that declare the stage.
func (r *Registry) orderStage(stage contracts.GateStage) ([]contracts.Gate, error) {
	nodes := map[string]contracts.Gate{}
	for _, g := range r.gates {
		if r.declared[g.ID()].Stages.Has(stage) {
			nodes[g.ID()] = g
		}
	}
	if len(nodes) == 0 {
		return nil, nil
	}

	writers := map[contracts.DataField][]string{}
	for id, d := range r.declared {
		if !d.Stages.Has(stage) {
			continue
		}
		for _, f := range d.Writes {
			writers[f] = append(writers[f], id)
		}
	}
	edges := map[string]map[string]bool{}
	addEdge := func(from, to string) {
		if from == to {
			return
		}
		if edges[from] == nil {
			edges[from] = map[string]bool{}
		}
		edges[from][to] = true
	}
	for id, d := range r.declared {
		if !d.Stages.Has(stage) {
			continue
		}
		for _, f := range d.Reads {
			for _, w := range writers[f] {
				addEdge(w, id)
			}
		}
		for _, a := range d.After {
			if _, ok := nodes[a]; ok {
				addEdge(a, id)
			}
		}
	}
	return kahn(nodes, edges)
}

// kahn is the deterministic topological sort. Among the nodes with in-degree
// zero it always picks the lexicographically smallest ID, so the output is
// stable across runs and machines. A remaining node after the queue empties is a
// cycle, reported with the names still on it.
func kahn(nodes map[string]contracts.Gate, edges map[string]map[string]bool) ([]contracts.Gate, error) {
	indegree := make(map[string]int, len(nodes))
	for id := range nodes {
		indegree[id] = 0
	}
	for _, tos := range edges {
		for to := range tos {
			indegree[to]++
		}
	}
	ready := make([]string, 0, len(nodes))
	for id, d := range indegree {
		if d == 0 {
			ready = append(ready, id)
		}
	}

	out := make([]contracts.Gate, 0, len(nodes))
	placed := 0
	for len(ready) > 0 {
		sort.Strings(ready)
		id := ready[0]
		ready = ready[1:]
		out = append(out, nodes[id])
		placed++
		for to := range edges[id] {
			indegree[to]--
			if indegree[to] == 0 {
				ready = append(ready, to)
			}
		}
	}

	if placed != len(nodes) {
		var cycle []string
		for id, d := range indegree {
			if d > 0 {
				cycle = append(cycle, id)
			}
		}
		sort.Strings(cycle)
		return nil, bootError("gate dependency cycle among: "+strings.Join(cycle, ", "), cycle)
	}
	return out, nil
}

// writesSecurityField reports whether a write set includes a field whose effect
// a FailOpen gate must not mask (ADR-0014 §3.4).
func writesSecurityField(writes []contracts.DataField) bool {
	for _, f := range writes {
		if f == contracts.FieldPII || f == contracts.FieldInjectionFlag {
			return true
		}
	}
	return false
}

// isPostOnly reports whether a stage set is exactly the post-response stage.
func isPostOnly(s contracts.GateStageSet) bool {
	return s.Has(contracts.StagePostResponse) &&
		!s.Has(contracts.StagePreRequest) &&
		!s.Has(contracts.StageOnResponseChunk)
}

// bootError is a wiring error (ADR-0014 §1.4): error.internal, because a bad
// gate graph is a bug in the binary, never the operator's request.
func bootError(reason string, names []string) error {
	params := map[string]string{"reason": reason}
	if len(names) > 0 {
		params["gates"] = strings.Join(names, ",")
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(500),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(params),
	)
}
