package combos

import (
	"regexp"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file holds the pure validation of a combo: shape (name, strategy, step
// targets) and graph (references resolve, no cycle, depth cap, fan-out cap,
// provider allowlist). It has no I/O and no clock, so it is fully testable.
//
// Validation runs at SAVE (ADR-0013 §3), never on the request path.

// nameRe is the combo-name grammar: [a-zA-Z0-9_.-]+, unique. The restricted
// charset keeps a name safe in a URL, in JSON and in the `model:` reference
// parser.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// IsValidName reports whether a combo name matches the grammar.
func IsValidName(name string) bool { return nameRe.MatchString(name) }

// invalid builds a route.invalid_combo error (ScopeRequest, non-retryable): a
// malformed combo is the operator's input problem and must never cooldown a
// credential or retry.
func invalid(name, reason string) error {
	return domain.New(domain.CodeRouteInvalidCombo,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "reason": reason}),
	)
}

// cyclic builds a route.cyclic_combo error naming the combo that closes the
// cycle.
func cyclic(name string) error {
	return domain.New(domain.CodeRouteCyclicCombo,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name}),
	)
}

// depthExceeded builds a route.depth_exceeded error.
func depthExceeded(name string) error {
	return domain.New(domain.CodeRouteDepthExceeded,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "max": itoa(MaxDepth)}),
	)
}

// fanoutExceeded builds a route.fanout_exceeded error.
func fanoutExceeded(name string) error {
	return domain.New(domain.CodeRouteFanoutExceeded,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "max": itoa(MaxFanout)}),
	)
}

// unknownProvider builds a route.unknown_provider error.
func unknownProvider(name, provider string) error {
	return domain.New(domain.CodeRouteUnknownProvider,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "provider": provider}),
	)
}

// Validate checks the SHAPE of one combo: name, strategy, step count and each
// step's target. It does NOT resolve references (ValidateGraph does).
func (c Combo) Validate() error {
	if !IsValidName(c.Name) {
		return invalid(c.Name, "name must match [a-zA-Z0-9_.-]+")
	}
	if _, ok := contractsParseStrategy(string(c.Strategy)); !ok {
		return invalid(c.Name, "unknown strategy")
	}
	if len(c.Steps) == 0 {
		return invalid(c.Name, "combo has no steps")
	}
	for i, s := range c.Steps {
		if !s.Kind.IsKnown() {
			return invalid(c.Name, "step "+itoa(i)+" has an unknown kind")
		}
		if s.Ref == "" {
			return invalid(c.Name, "step "+itoa(i)+" has an empty reference")
		}
	}
	return nil
}

// ValidateGraph checks the DAG properties of a combo against the set of combos
// it may reference. `existing` must contain the targets of every StepComboRef;
// the combo being saved is passed separately (`self`) because it may not be in
// `existing` yet (a create).
//
// It returns the combo's depth (the longest chain of references from it), so the
// caller can store it. Errors are typed route.*.
func ValidateGraph(c Combo, existing map[domain.ComboID]Combo, providers ProviderSet) (depth int, err error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}

	// Provider allowlist (ADR-0013 §3.6): every concrete target must resolve to
	// a known provider. StepComboRef is checked by resolution, not here. A nil
	// provider set is an explicit opt-out (the caller has no registry to consult)
	// and skips the check rather than refusing every target.
	if providers != nil {
		for _, s := range c.Steps {
			switch s.Kind {
			case StepProviderWildcard:
				if !providers.Has(domain.ProviderID(s.Ref)) {
					return 0, unknownProvider(c.Name, s.Ref)
				}
			case StepModel:
				if !providers.DeclaresModel(domain.ModelID(s.Ref)) {
					return 0, unknownProvider(c.Name, s.Ref)
				}
			}
		}
	}

	// Reference resolution: every combo-ref exists in `existing` (or is self,
	// which is a self-cycle and therefore always invalid).
	for _, s := range c.Steps {
		if s.Kind != StepComboRef {
			continue
		}
		if s.Ref == c.Name {
			return 0, cyclic(c.Name)
		}
		if _, ok := existing[domain.ComboID(s.Ref)]; !ok {
			return 0, invalid(c.Name, "reference to unknown combo "+s.Ref)
		}
	}

	// Fusion fan-out cap (ADR-0013 §3.5): a fusion combo runs its steps in
	// parallel, so the step count IS the fan-out.
	if c.Strategy == contractsStrategyFusion() && len(c.Steps) > MaxFanout {
		return 0, fanoutExceeded(c.Name)
	}

	// Cycle detection + depth by DFS over the reference graph. The graph is
	// `existing` plus `self` (a create adds self before referencing anything).
	graph := make(map[domain.ComboID]Combo, len(existing)+1)
	for id, other := range existing {
		graph[id] = other
	}
	graph[c.ID] = c

	// White (unvisited) / grey (on stack) / black (done). Grey on the stack is a
	// back-edge => cycle.
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := map[domain.ComboID]int{}
	var depthOf func(id domain.ComboID) (int, error)
	depthOf = func(id domain.ComboID) (int, error) {
		switch state[id] {
		case grey:
			return 0, cyclic(string(id))
		case black:
			return graph[id].Depth, nil
		}
		node, ok := graph[id]
		if !ok {
			// A reference that does not resolve. Already reported for `self`;
			// this guards a malformed `existing` set.
			return 0, invalid(string(id), "reference to unknown combo")
		}
		state[id] = grey
		maxChild := 0
		for _, s := range node.Steps {
			if s.Kind != StepComboRef {
				continue
			}
			childDepth, err := depthOf(domain.ComboID(s.Ref))
			if err != nil {
				return 0, err
			}
			if childDepth+1 > maxChild {
				maxChild = childDepth + 1
			}
		}
		state[id] = black
		graph[id] = withDepth(node, maxChild)
		return maxChild, nil
	}

	depth, err = depthOf(c.ID)
	if err != nil {
		return 0, err
	}
	if depth > MaxDepth {
		return 0, depthExceeded(c.Name)
	}
	return depth, nil
}

// withDepth returns a copy of node with Depth set, without mutating the input.
func withDepth(node Combo, depth int) Combo {
	node.Depth = depth
	return node
}
